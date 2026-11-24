"""The SQL reader: from a statement to the atomic operations it performs. No rule here.

    read_sql(text, schema) -> set of (operation, table, column)
        operation: read, insert, update, delete, structure, transaction
        schema: {"tables": {name: [columns]}, "views": {name: "SELECT ..."}}

A read through a view is a read of everything the view's definition reads. A statement that cannot be parsed, or
names something the schema does not have, raises ValueError: the gate then does not let it pass.
"""
import logging

import sqlglot
from sqlglot import exp

logging.getLogger("sqlglot").setLevel(logging.ERROR)
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import traverse_scope


QUERIES = (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery)       # everything that only reads


def _arg(node, name):
    """sqlglot names some arguments with a trailing underscore in newer versions."""
    return node.args.get(name) or node.args.get(name + "_")


def _reads(query, schema, cache, skip_empty=None):
    tables, views = schema["tables"], schema.get("views", {})
    known = {**{t: {c: "TEXT" for c in cols} for t, cols in tables.items()},
             **{v: {c: "TEXT" for c in _view_cols(v, schema, cache)} for v in views}}
    for sel in query.find_all(exp.Select):      # the same name twice in one FROM: the database calls it ambiguous
        srcs = [x.this for x in [_arg(sel, "from")] + (sel.args.get("joins") or []) if x is not None]
        named = [x.alias_or_name.lower() for x in srcs if isinstance(x, (exp.Table, exp.Subquery)) and x.alias_or_name]
        if len(named) != len(set(named)):
            raise ValueError("the same table name twice without an alias")
    q = qualify(query.copy(), schema=known, dialect=schema.get("dialect", "sqlite"), quote_identifiers=False, validate_qualify_columns=True)
    out = set()
    for scope in traverse_scope(q):
        used = {}
        for col in scope.columns:
            used.setdefault(col.table, set()).add(col.name)
        for alias, src in scope.sources.items():
            if not isinstance(src, exp.Table):
                continue
            name = src.name
            if name in views:
                out |= _view_reads(name, schema, cache)
            elif name in tables:
                cols = used.get(alias, set())
                for c in cols:
                    if c not in tables[name]:
                        raise ValueError(f"no column {c} in {name}")
                    out.add(("read", name, c))
                if not cols and name != skip_empty:
                    out.add(("read", name, ""))
            else:
                raise ValueError(f"no table {name}")
    return out


def _view_cols(name, schema, cache):
    key = ("cols", name)
    if key not in cache:
        sel = sqlglot.parse_one(schema["views"][name], read=schema.get("dialect", "sqlite"))
        cache[key] = [e.alias_or_name for e in sel.selects]
    return cache[key]


def _view_reads(name, schema, cache):
    key = ("reads", name)
    if key not in cache:
        cache[key] = set()                      # a view that names itself reads nothing more
        cache[key] = _reads(sqlglot.parse_one(schema["views"][name], read=schema.get("dialect", "sqlite")), schema, cache)
    return cache[key]


def _change_offsets(text, dialect):
    """`UPDATE ... LIMIT n OFFSET m` and `DELETE ... LIMIT n OFFSET m`, which the parser does not take: the text with
    each such OFFSET cut out, and the offsets by statement. Found on tokens, so a string that holds the words is not
    touched; anything else is left as it was."""
    from sqlglot.tokens import TokenType as T
    toks = [t for t in sqlglot.Dialect.get_or_raise(dialect).tokenize(text)]
    cut, offsets, first, n = [], {}, 0, 0
    for i, t in enumerate(toks + [None]):
        if t is not None and t.token_type != T.SEMICOLON:
            continue
        st = toks[first:i]
        if (len(st) >= 4 and st[0].token_type in (T.UPDATE, T.DELETE) and st[-4].token_type == T.LIMIT
                and st[-3].token_type == T.NUMBER and st[-2].token_type == T.OFFSET and st[-1].token_type == T.NUMBER):
            cut.append((st[-2].start, st[-1].end + 1))
            offsets[n] = int(st[-1].text)
        first, n = i + 1, n + 1
    for a, b in reversed(cut):
        text = text[:a] + text[b:]
    return text, offsets


def _row_ops(s, schema):
    """Which rows of each table a statement touches, as queries the gate can count on the live database (only when the
    schema says `"row_rules": true`). Read by the engine against the container's row conditions.

    - every SELECT (the statement itself, a subquery, the source of an INSERT): for each table in its FROM and JOINs,
      `SELECT <t>.* FROM <its FROM and JOINs> WHERE <its WHERE>`, with ORDER BY, LIMIT and OFFSET kept when it reads one
      table, and no query (not read) when it limits rows of a join;
    - UPDATE and DELETE: the rows of the table their WHERE selects, and whether the statement reads the table's columns
      (in WHERE, SET or RETURNING); UPDATE also the rows as they would be after it (`update_check`);
    - INSERT: the new rows, with the columns it leaves out as NULL (`insert_check`), read when it has RETURNING.
    Values are cast to the column's type from `schema["types"]` when it has one."""
    import json as _json
    dialect = schema.get("dialect", "sqlite")
    tables, types = schema["tables"], schema.get("types", {})
    with_ = _arg(s, "with")
    ctes = {c.alias_or_name for c in with_.expressions} if with_ else set()
    ops = set()

    def emit(right, t, q, reads=False):
        if q is not None and with_ is not None:
            q.set("with_" if "with_" in s.args else "with", with_.copy())
        ops.add(("rows", t, _json.dumps({"right": right, "reads": reads, "rows": q.sql(dialect=dialect) if q is not None else None},
                                        sort_keys=True)))

    def cast(e, t, col):
        ty = types.get(t, {}).get(col)
        return exp.Cast(this=e, to=exp.DataType.build(ty, dialect=dialect)) if ty else e

    def column_reads(nodes):
        for n in nodes:
            for col in ([n] if isinstance(n, exp.Column) else []) + list(n.find_all(exp.Column)):
                if col.find_ancestor(exp.Select) is None:      # a column of the statement itself, not of a subquery
                    return True
        return False

    for sel in s.find_all(exp.Select):
        srcs = [x for x in [_arg(sel, "from")] + (sel.args.get("joins") or []) if x is not None]
        tabs = [x.this for x in srcs if isinstance(x.this, exp.Table) and x.this.name in tables and x.this.name not in ctes]
        for tab in tabs:
            limited = sel.args.get("limit") or sel.args.get("offset")
            if limited and (len(srcs) > 1 or not sel.args.get("order")):
                emit("read", tab.name, None)
                continue
            q = exp.select(exp.Column(this=exp.Star(), table=exp.to_identifier(tab.alias_or_name)))
            q.set("from_" if "from_" in sel.args else "from", srcs[0].copy())
            if sel.args.get("joins"):
                q.set("joins", [j.copy() for j in sel.args["joins"]])
            for k in ("where", "order", "limit", "offset") if limited else ("where",):
                if sel.args.get(k):
                    q.set(k, sel.args[k].copy())
            emit("read", tab.name, q)
    if isinstance(s, (exp.Update, exp.Delete)):
        t, where = s.this.name, s.args.get("where")
        if t in tables:
            sets = {a.this.name: a.expression for a in s.expressions} if isinstance(s, exp.Update) else {}
            returning = s.args.get("returning")
            reads = column_reads(([where.this] if where else []) + list(sets.values()) + (list(returning.expressions) if returning else []))
            base = exp.select(exp.Column(this=exp.Star(), table=exp.to_identifier(s.this.alias_or_name))).from_(s.this.copy())
            if where:
                base = base.where(where.this.copy())
            emit("update" if isinstance(s, exp.Update) else "delete", t, base, reads)
            if isinstance(s, exp.Update):
                new = exp.select(*[exp.alias_(cast(sets[c].copy(), t, c) if c in sets else exp.column(c, table=s.this.alias_or_name), c)
                                   for c in tables[t]]).from_(s.this.copy())
                if where:
                    new = new.where(where.this.copy())
                emit("update_check", t, new, reads)
    elif isinstance(s, exp.Insert):
        target = s.this.this if isinstance(s.this, exp.Schema) else s.this
        t = target.name
        if t in tables:
            given = [c.name for c in s.this.expressions] if isinstance(s.this, exp.Schema) else None
            src = s.expression
            width = len(src.expressions[0].expressions) if isinstance(src, exp.Values) and src.expressions else len(src.selects) if isinstance(src, exp.Select) else None
            if given is None and width is not None:
                given = tables[t][:width]
            if given is None or width is None or width != len(given):
                emit("insert_check", t, None, bool(s.args.get("returning")))
            else:
                names = [f"gate_c{i}" for i in range(len(given))]   # each value named, as every SQL database reads it
                if isinstance(src, exp.Values):
                    inner = None
                    for tup in src.expressions:
                        one = exp.select(*[exp.alias_(v.copy(), n) for v, n in zip(tup.expressions, names)])
                        inner = one if inner is None else exp.union(inner, one, distinct=False)
                else:
                    inner = src.copy()
                    inner.set("expressions", [exp.alias_(e.this.copy() if isinstance(e, exp.Alias) else e.copy(), n)
                                              for e, n in zip(src.selects, names)])
                derived = exp.Subquery(this=inner, alias=exp.TableAlias(this=exp.to_identifier("gate_new")))
                cols = [exp.alias_(cast(exp.column(names[given.index(c)], table="gate_new"), t, c) if c in given
                                   else cast(exp.Null(), t, c), c) for c in tables[t]]
                emit("insert_check", t, exp.select(*cols).from_(derived), bool(s.args.get("returning")))
    return ops


def read_sql(text, schema):
    offsets = {}
    try:
        statements = sqlglot.parse(text, read=schema.get("dialect", "sqlite"))
    except Exception as e:  # noqa: BLE001
        try:
            cleaned, offsets = _change_offsets(text, schema.get("dialect", "sqlite"))
            if not offsets:
                raise ValueError
            statements = sqlglot.parse(cleaned, read=schema.get("dialect", "sqlite"))
        except Exception:  # noqa: BLE001
            raise ValueError(f"not parsed: {e}") from None
    offset_of = {id(x): offsets[i] for i, x in enumerate(statements) if i in offsets}
    if not statements or any(s is None for s in statements):
        raise ValueError("empty statement")
    tx_kinds = (exp.Transaction, exp.Commit, exp.Rollback)
    changes = sum(not isinstance(x, QUERIES) and not (isinstance(x, tx_kinds) and not x.args.get("savepoint"))
                  for x in statements)          # opening or closing the session's transaction changes no data
    cache, ops, tables, tx_steps = {}, {("statements", len(statements), changes)}, schema["tables"], []
    try:
        for s in statements:
            if s.find(exp.Placeholder, exp.Parameter):
                raise ValueError("a placeholder with no value")
            if schema.get("row_rules"):
                ops |= _row_ops(s, schema)
            for f in s.find_all(exp.Func):                  # every function the statement calls, by name
                if isinstance(f, (exp.Binary, exp.Unary, exp.Predicate)):
                    continue                                # AND, OR, NOT, comparisons: operators, not functions
                ops.add(("function", (f.name if isinstance(f, exp.Anonymous) else f.sql_name()).lower(), None))
            if isinstance(s, QUERIES) or (isinstance(s, exp.With) and False):
                ops |= _reads(s, schema, cache)
            elif isinstance(s, exp.Insert):
                t = s.this.this.name if isinstance(s.this, exp.Schema) else s.this.name
                if t not in tables:
                    raise ValueError(f"no table {t}")
                ops.add(("insert", t, None))
                if s.args.get("alternative") or s.args.get("conflict") or _arg(s, "replace"):
                    ops.add(("replace", t, None))           # an insert that can replace or change rows already there
                if s.args.get("returning"):                 # what an insert gives back is read
                    ops |= _reads(exp.select(*[e.copy() for e in s.args["returning"].expressions]).from_(exp.to_table(t)), schema, cache, skip_empty=t)
                src = s.expression
                if isinstance(src, QUERIES):
                    if _arg(s, "with"):
                        src = exp.Subquery(this=src.copy()) if False else src.copy()
                        src.set("with_" if "with_" in s.args else "with", _arg(s, "with").copy())
                    ops |= _reads(src, schema, cache)
            elif isinstance(s, (exp.Update, exp.Delete)):
                t = s.this.name
                if t not in tables:
                    raise ValueError(f"no table {t}")
                parts = []
                if isinstance(s, exp.Update):
                    for a in s.expressions:
                        col = a.this.name
                        if col not in tables[t]:
                            raise ValueError(f"no column {col} in {t}")
                        ops.add(("update", t, col))
                        parts.append(a.expression.copy())
                else:
                    ops.add(("delete", t, None))
                where = s.args.get("where")
                if s.args.get("returning"):                 # what a change gives back is read
                    parts += [e.copy() for e in s.args["returning"].expressions]
                if _arg(s, "from"):
                    raise ValueError("a change with FROM is not read")
                limit, order = s.args.get("limit"), s.args.get("order")
                offset = offset_of.get(id(s))
                if offset is not None and not limit:
                    raise ValueError("an OFFSET with no LIMIT")
                if limit or order:                          # some databases take ORDER BY and LIMIT on a change, some do not
                    if not schema.get("change_limit") or not limit:
                        raise ValueError("this database does not take ORDER BY or LIMIT on a change")
                    parts += [o.this.copy() for o in (order.expressions if order else [])]
                    inner = exp.select("1").from_(s.this.copy())
                    if where:
                        inner = inner.where(where.this.copy())
                    for name, node in (("order", order), ("limit", limit)):
                        if node:
                            inner.set(name, node.copy())
                    if offset is not None:
                        inner = inner.offset(offset)
                    count = exp.select("count(*)").from_(inner.subquery("counted"))
                else:
                    count = exp.select("count(*)").from_(s.this.copy())
                    if where:
                        count = count.where(where.this.copy())
                if _arg(s, "with"):
                    count.set("with_" if "with_" in s.args else "with", _arg(s, "with").copy())
                ops.add(("update_rows" if isinstance(s, exp.Update) else "delete_rows", t, count.sql(dialect=schema.get("dialect", "sqlite"))))
                if parts or where:
                    probe = exp.select(*(parts or [exp.Literal.number(1)])).from_(s.this.copy())
                    if where:
                        probe = probe.where(where.this.copy())
                    if _arg(s, "with"):
                        probe.set("with_" if "with_" in s.args else "with", _arg(s, "with").copy())
                    ops |= _reads(probe, schema, cache, skip_empty=t)
            elif (isinstance(s, exp.Drop) and s.args.get("exists") and schema.get("live")
                  and all(x.name not in tables and x.name not in schema.get("views", {}) for x in s.args.get("tables") or [])
                  and (s.args.get("kind") or "").upper() in ("TABLE", "VIEW")):
                pass                                        # DROP ... IF EXISTS of a name the database does not have: nothing happens
            elif isinstance(s, (exp.Transaction, exp.Commit, exp.Rollback)) and not s.args.get("savepoint"):
                tx_steps.append(type(s).__name__.lower())   # opens or closes the session's own transaction, in order
            else:
                ops.add(("structure", type(s).__name__, None))
    except ValueError:
        raise
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"not understood: {type(e).__name__}: {e}") from None
    if tx_steps:                            # one operation for the text's transaction statements, in their order
        ops.add(("transaction", ">".join(tx_steps), None))
    return ops

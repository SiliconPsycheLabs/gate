"""A MongoDB operation read into the privilege actions it needs. Software, holds no rule of its own.

    read_mongo(op, schema) -> {(action, "db.collection" or "db", None), ...}

`op` is `{"op": ..., "collection": ..., "details": {...}}` on the database `schema["db"]` (`details`: `filter`, `upsert`,
`many`, `remove`, `pipeline`), as a tool that calls the driver takes it.
The actions are MongoDB's own privilege actions (the "Required Access" of each command in MongoDB's manual):
- `find`, `count`, `distinct`: `find` on the collection;
- `insert`: `insert`, also on a collection that does not exist yet (the insert creates it and MongoDB asks for no
  `createCollection`);
- `update` and `replace`: `update`, and `insert` with `upsert`;
- `delete`: `remove`;
- `findAndModify`: `find` and `update` (`insert` with `upsert`), or `find` and `remove` with `remove: true`;
- `aggregate`: `find` on the collection and on every collection a stage reads (`$lookup`, `$graphLookup`,
  `$unionWith`, nested pipelines and `$facet` included); `$out` needs `insert` and `remove` on its target, `$merge`
  `insert` when it may insert and `update` when it may change a matching document (`_merge_rights`);
- `drop`: `dropCollection`; `createIndex`: `createIndex`; `listCollections`: `listCollections` on the database.
An operation or a stage the reader does not know raises `ValueError` and does not pass.
"""

_READ_STAGES = {"$match", "$project", "$addFields", "$set", "$unset", "$group", "$sort", "$limit", "$skip", "$count",
                "$unwind", "$sample", "$replaceRoot", "$replaceWith", "$bucket", "$sortByCount", "$redact"}


def _merge_rights(arg):
    """The rights `$merge` asks on its target, as MongoDB 8.0 checks them (asked of the server, every pair of modes):
    `insert` when a document with no match is inserted, `update` when a matching one is changed; `keepExisting` and
    `fail` with no insert are refused by the server (error 51181), so they do not pass here either."""
    if isinstance(arg, str):
        return ("insert", "update")
    matched, unmatched = arg.get("whenMatched", "merge"), arg.get("whenNotMatched", "insert")
    if not isinstance(matched, list) and matched not in ("replace", "merge", "keepExisting", "fail"):
        raise ValueError(f"$merge whenMatched the reader does not read: {matched!r}")
    if unmatched not in ("insert", "discard", "fail"):
        raise ValueError(f"$merge whenNotMatched the reader does not read: {unmatched!r}")
    if unmatched != "insert":
        if matched in ("keepExisting", "fail"):
            raise ValueError("$merge that neither inserts nor changes a document: the server refuses it")
        return ("update",)
    return ("insert",) if matched == "fail" else ("insert", "update")


def _pipeline(stages, db, ops, top):
    if not isinstance(stages, list):
        raise ValueError("a pipeline is a list of stages")
    for i, st in enumerate(stages):
        if not isinstance(st, dict) or len(st) != 1:
            raise ValueError("a stage is an object with one key")
        (name, arg), = st.items()
        if name in _READ_STAGES:
            continue
        if name in ("$lookup", "$graphLookup"):
            if not isinstance(arg, dict):
                raise ValueError(f"{name} takes an object")
            if arg.get("from"):
                ops.add(("find", f"{db}.{arg['from']}", None))
            if "pipeline" in arg:
                _pipeline(arg["pipeline"], db, ops, False)
        elif name == "$unionWith":
            coll = arg if isinstance(arg, str) else (arg or {}).get("coll")
            if not isinstance(coll, str):
                raise ValueError("$unionWith names a collection")
            ops.add(("find", f"{db}.{coll}", None))
            if isinstance(arg, dict) and "pipeline" in arg:
                _pipeline(arg["pipeline"], db, ops, False)
        elif name == "$facet":
            if not isinstance(arg, dict):
                raise ValueError("$facet takes an object")
            for sub in arg.values():
                _pipeline(sub, db, ops, False)
        elif name in ("$out", "$merge") and top and i == len(stages) - 1:
            target = arg if isinstance(arg, str) else (arg if name == "$out" else arg.get("into"))
            if isinstance(target, dict):             # {"db": ..., "coll": ...}: another database is not read
                if target.get("db", db) != db:
                    raise ValueError(f"{name} to another database")
                target = target.get("coll")
            if not isinstance(target, str):
                raise ValueError(f"{name} names a collection")
            for a in (("insert", "remove") if name == "$out" else _merge_rights(arg)):
                ops.add((a, f"{db}.{target}", None))
        else:
            raise ValueError(f"a stage the reader does not read: {name}")


def read_mongo(op, schema):
    if not isinstance(op, dict):
        raise ValueError("an operation is an object")
    if isinstance(op.get("details"), dict):            # the door's form: op, collection and the rest under details
        op = {**op["details"], "op": op.get("op"), "collection": op.get("collection")}
    db, kind, coll = schema["db"], op.get("op"), op.get("collection")
    if kind == "listCollections":
        return {("listCollections", db, None)}
    if not isinstance(coll, str) or not coll or coll.startswith("system.") or "$" in coll:
        raise ValueError("an operation names a collection")
    name = f"{db}.{coll}"
    ops = set()
    if kind in ("find", "count", "distinct"):
        ops.add(("find", name, None))
    elif kind == "insert":
        ops.add(("insert", name, None))     # a collection that does not exist is created by the insert: MongoDB asks
                                            # for `insert` alone, not `createCollection`
    elif kind in ("update", "replace"):
        ops.add(("update", name, None))
        if op.get("upsert"):
            ops.add(("insert", name, None))
    elif kind == "delete":
        ops.add(("remove", name, None))
    elif kind == "findAndModify":
        ops.add(("find", name, None))
        if op.get("remove"):
            ops.add(("remove", name, None))
        else:
            ops.add(("update", name, None))
            if op.get("upsert"):
                ops.add(("insert", name, None))
    elif kind == "aggregate":
        ops.add(("find", name, None))
        _pipeline(op.get("pipeline", []), db, ops, True)
    elif kind == "drop":
        ops.add(("dropCollection", name, None))
    elif kind == "createIndex":
        ops.add(("createIndex", name, None))
    else:
        raise ValueError(f"an operation the reader does not read: {kind!r}")
    return ops

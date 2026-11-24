"""The gate on the table engine: the rules are a table, the software only reads it.

Nothing here knows a company, a product or a web framework. A table lists what an agent may do; the engine reads it
and gives every action one of two answers: it passes, or it does not pass with a fixed reason.

    engine.py     the engine: a table's tools (doors), their forms and conditions, and the language doors
    reader_*.py   the translators: a text in a language (SQL, shell, HTTP, mail, pip, MongoDB, ...) read into the
                  operations it performs, each checked against what the table opens
    shape.py      the shape of an action: the same operation on the same resource asked in the same form
    recorder.py   one decision as a log record: form, decide, answer, what was read, the rule that decided
    view.py       how the gate reads the company's system: the calls of a connector, guarded so that a system
                  that does not answer lets nothing pass; a reference connector on SQLite
    manager.py    the action manager: translate, form, decide, answer, record; `ran`, `release` and `open_once`
    trial.py      a table tried on recorded actions
    validate.py   whether a document is a table the engine can read

`__version__` is the version of the engine.
"""

__version__ = "2.5.0"

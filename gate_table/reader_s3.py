"""The S3 reader: from an API call to the action it needs on the resource it touches. No rule here.

    read_s3(call, schema) -> set of (action, resource, None)
        call: {"operation": "GetObject", "bucket": "inv", "key": "a.txt"}  (and "source_bucket", "source_key" for a copy)
        resource: "bucket/key", or "bucket/" for an operation on the bucket itself
        schema: {"operations": which action each call needs and whether it acts on an object or on the bucket}

The list of operations is data (tables/s3_operations.json), copied from AWS's published list of S3 actions.
"""
import posixpath


def read_s3(call, schema):
    op = schema["operations"].get(call.get("operation"))
    if op is None:
        raise ValueError("unknown operation")
    bucket, key = call.get("bucket", ""), call.get("key", "")
    if op["on"] == "account":
        return {(op["action"], "/", None)}
    if not bucket:
        raise ValueError("no bucket")
    if op["on"] == "bucket":
        return {(op["action"], bucket + "/", None)}
    if not key:
        raise ValueError("no key")
    ops = {(op["action"], bucket + ("" if key.startswith("/") else "/") + key, None)}
    if "source_action" in op:                   # a copy reads one object and writes another
        sb, sk = call.get("source_bucket", ""), call.get("source_key", "")
        if not sb or not sk:
            raise ValueError("no source")
        ops.add((op["source_action"], sb + ("" if sk.startswith("/") else "/") + sk, None))
    return ops


def wildcard(pattern, text):
    """* is any run of characters, ? is one character; everything else is itself."""
    p = t = 0
    star = mark = -1
    while t < len(text):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]) and pattern[p] != "*":
            p, t = p + 1, t + 1
        elif p < len(pattern) and pattern[p] == "*":
            star, mark, p = p, t, p + 1
        elif star != -1:
            p, mark = star + 1, mark + 1
            t = mark
        else:
            return False
    return all(c == "*" for c in pattern[p:])


def s3_resource(pattern, resource):
    """MinIO's resource match: the pattern after the ARN prefix, against bucket/key."""
    pattern = pattern[len("arn:aws:s3:::"):] if pattern.startswith("arn:aws:s3:::") else pattern
    clean = posixpath.normpath(resource) if resource else "."
    return (clean != "." and clean == pattern) or wildcard(pattern, resource)

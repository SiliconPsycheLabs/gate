"""A Terraform plan read into operations. Software, holds no rule of its own.

    read_tfplan(plan, schema=None) -> {(operation, resource type, part), ...}

`plan` is the plan as `terraform show -json` prints it. Each entry of `resource_changes` whose `mode` is `managed` and
whose actions are not only `no-op` is read (data sources and no-ops change nothing):
- `("change", <type>, <action>)` for each of its actions (`create`, `update`, `delete`, `read`; a replacement is both
  delete and create);
- for a resource the plan creates or updates, from the values after the change (`change.after`):
  - `("tag", <type>, "Owner")` when `tags.Owner` is a non-empty string, else `("tag", <type>, "Owner missing")`;
  - `("instance_type", <type>, <value>)` for `aws_instance` (`unknown` when the plan does not set it or does not know it
    yet: the rules see the value, so a value they cannot see does not pass);
  - `("acl", <type>, <value>)` for `aws_s3_bucket` when the plan sets an ACL;
  - `("ingress", <type>, "ssh from 0.0.0.0/0")` for `aws_security_group` when an ingress rule opens port 22 (its
    `from_port` and `to_port` numbers around 22) to `0.0.0.0/0`; a port written as text or null is not read
    (`ValueError`);
  - `("policy_arn", <type>, <value>)` for `aws_iam_role_policy_attachment`.
A plan that is not an object with a list of `resource_changes` raises `ValueError`.
"""


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def read_tfplan(plan, schema=None):
    if isinstance(plan, dict) and "plan" in plan and "resource_changes" not in plan:
        plan = plan["plan"]                       # the door's form: the plan under one field
    if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes"), list):
        raise ValueError("a plan has a list of resource_changes")
    ops = set()
    for rc in plan["resource_changes"]:
        if not isinstance(rc, dict) or rc.get("mode") != "managed":
            continue
        ch = rc.get("change") or {}
        actions = ch.get("actions") or []
        if actions == ["no-op"]:
            continue
        t = str(rc.get("type"))
        for a in actions:
            ops.add(("change", t, str(a)))
        if "create" not in actions and "update" not in actions:
            continue
        after = ch.get("after") if isinstance(ch.get("after"), dict) else {}
        if t != "aws_iam_role_policy_attachment":
            tags = after.get("tags") if isinstance(after.get("tags"), dict) else {}
            o = tags.get("Owner")
            ops.add(("tag", t, "Owner" if isinstance(o, str) and o != "" else "Owner missing"))
        if t == "aws_instance":
            v = after.get("instance_type")
            ops.add(("instance_type", t, v if isinstance(v, str) else "unknown"))
        if t == "aws_s3_bucket" and "acl" in after and after["acl"] is not None:
            ops.add(("acl", t, str(after["acl"])))
        if t == "aws_security_group":
            for rule in after.get("ingress") or []:
                if not isinstance(rule, dict):
                    continue
                cidrs = rule.get("cidr_blocks") if isinstance(rule.get("cidr_blocks"), list) else []
                for k in ("from_port", "to_port"):          # a port the plan writes is a number; text or null is
                    if k in rule and not _num(rule[k]):    # not read (Rego would compare it by type)
                        raise ValueError(f"a port that is not a number: {k} = {rule[k]!r}")
                fp, tp = rule.get("from_port"), rule.get("to_port")
                if "0.0.0.0/0" in cidrs and _num(fp) and _num(tp) and fp <= 22 <= tp:
                    ops.add(("ingress", t, "ssh from 0.0.0.0/0"))
        if t == "aws_iam_role_policy_attachment":
            v = after.get("policy_arn")
            ops.add(("policy_arn", t, v if isinstance(v, str) else "unknown"))
    return ops

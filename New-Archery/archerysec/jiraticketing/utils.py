def jira_issue_types(jira_ser):
    """Return a de-duplicated, ordered list of non-subtask issue type names
    available across all projects visible to the configured Jira connection."""
    types = set()
    try:
        meta = jira_ser.createmeta()
        for project in meta.get("projects", []) or []:
            for issue_type in project.get("issuetypes", []) or []:
                name = issue_type.get("name")
                if name and not issue_type.get("subtask"):
                    types.add(name)
    except Exception:
        return ["Story"]
    ordered = [t for t in ("Epic", "Story", "Bug", "Task") if t in types]
    ordered.extend(sorted(t for t in types if t not in ordered))
    return ordered or ["Story"]
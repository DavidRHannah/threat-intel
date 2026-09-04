"""mkdocs-gen-files hook: generate one API reference page per module under src/ and
infra/, plus a literate nav (reference/SUMMARY.md), so the reference tree always
matches the source tree with no hand-maintained page list."""

from pathlib import Path

import mkdocs_gen_files

nav = mkdocs_gen_files.Nav()

for root_name in ("src", "infra"):
    for path in sorted(Path(root_name).rglob("*.py")):
        module_path = path.with_suffix("")
        doc_path = path.with_suffix(".md")
        full_doc_path = Path("reference", doc_path)

        parts = list(module_path.parts)

        if parts[-1] == "__init__":
            parts = parts[:-1]
            if not parts:
                continue
            doc_path = doc_path.with_name("index.md")
            full_doc_path = full_doc_path.with_name("index.md")
        elif parts[-1] == "__main__":
            continue

        nav[parts] = doc_path.as_posix()

        identifier = ".".join(parts)
        with mkdocs_gen_files.open(full_doc_path, "w") as fd:
            fd.write(f"# `{identifier}`\n\n::: {identifier}\n")

        mkdocs_gen_files.set_edit_path(full_doc_path, path)

with mkdocs_gen_files.open("reference/SUMMARY.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())

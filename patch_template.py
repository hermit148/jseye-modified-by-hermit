"""Patch the showTab() function in report.html to scope tab switching to the
parent tab group container instead of the entire document."""
import pathlib, re, sys

template = pathlib.Path(
    r"jseye\report\templates\report.html"
)

content = template.read_text(encoding="utf-8")

# The pattern to find the showTab block (works with either \n or \r\n)
pattern = re.compile(
    r"function showTab\(e, tabId\) \{.*?\}(?=\s*\n\s*function)",
    re.DOTALL,
)

replacement = r"""function showTab(e, tabId) {
            // Scope to the parent tab group so multiple tab groups on the
            // same page don't interfere with each other.
            const clickedTab = e && e.currentTarget ? e.currentTarget : null;
            const tabGroup = clickedTab ? clickedTab.closest('.tabs') : null;

            if (tabGroup) {
                tabGroup.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                const section = tabGroup.closest('.section-content') || tabGroup.parentElement;
                if (section) {
                    section.querySelectorAll('.tab-content').forEach(c => {
                        c.classList.remove('active');
                    });
                }
            } else {
                // Fallback: affect entire document (original behaviour)
                document.querySelectorAll('.tab-content').forEach(c => {
                    c.classList.remove('active');
                });
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
            }

            // Show selected tab content
            const target = document.getElementById(tabId);
            if (target) target.classList.add('active');

            // Mark clicked tab as active
            if (clickedTab) clickedTab.classList.add('active');
        }"""

new_content, n = pattern.subn(replacement, content, count=1)
if n == 0:
    print("ERROR: pattern not found — template was not modified", file=sys.stderr)
    sys.exit(1)

template.write_text(new_content, encoding="utf-8")
print(f"OK: showTab() patched in {template}")

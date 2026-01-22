# Remove AI code slop

Check the diff against main, and remove all AI generated slop introduced in this branch.

This includes:
- Extra comments that a human wouldn't add or is inconsistent with the rest of the file
- Extra defensive checks or try/catch blocks that are abnormal for that area of the codebase (especially if called by trusted / validated codepaths)
- Any type: ignore or cast that works around type issues instead of fixing them
- Unnecessary abstractions or over-engineering
- Any other style that is inconsistent with the file or project patterns

Report at the end with only a 1-3 sentence summary of what you changed.

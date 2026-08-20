# Bakes the migration files into the image instead of relying on a
# runtime bind mount for /docker-entrypoint-initdb.d. A bind mount here
# proved unreliable on Windows/Docker Desktop (see CLAUDE.md's incident
# log - the exact same class of problem already hit ansible/ once
# before this project switched that to a baked-in COPY too).
FROM postgres:16-alpine

COPY migrations/ /docker-entrypoint-initdb.d/

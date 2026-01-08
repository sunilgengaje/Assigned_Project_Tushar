# Copilot Instructions for AI Agents

## Project Overview
This is a FastAPI-based backend project with modular architecture. Key components are organized under the `app/` directory, which contains API routes, core utilities, database models, middleware, repositories, and services. Alembic is used for database migrations.

## Major Components
- **app/main.py**: FastAPI app entry point.
- **app/api/routes/**: API route definitions (e.g., `auth.py`, `manage_aggregator.py`).
- **app/core/**: Security, response utilities, and key/captcha stores.
- **app/db/**: Database session and base model setup.
- **app/models/**: SQLAlchemy models for all entities.
- **app/repositories/**: Data access logic (e.g., `user_repository.py`).
- **app/services/**: Business logic (e.g., `auth_service.py`).
- **alembic/**: Database migration scripts.

## Developer Workflows
- **Run backend**: Use VS Code task "Run FastAPI backend (main.py) as service" or run `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload` from the project root.
- **Database migrations**: Use Alembic CLI (`alembic upgrade head`, `alembic revision --autogenerate -m "message"`).
- **Virtual environment**: Activate with `source .venv/bin/activate`.
- **Dependencies**: Managed in `requirement.txt` (note: file name is not standard, check for typos).

## Project-Specific Patterns
- **API routes**: Grouped by domain in `app/api/routes/`. Use dependency injection via `app/api/deps.py`.
- **Models and schemas**: Models in `app/models/`, Pydantic schemas in `app/schemas/`.
- **Middleware**: Custom AES-GCM middleware in `app/middleware/aes_gcm_middleware.py`.
- **Logging**: Centralized in `app/api_logger.py`.
- **Response formatting**: Use helpers in `app/core/response_utils.py`.

## Integration Points
- **Database**: SQLAlchemy ORM, session managed in `app/db/session.py`.
- **Migrations**: Alembic (`alembic.ini`, `alembic/`).
- **Static/Template files**: Served from `app/static/` and `app/templates/`.

## Conventions
- **File structure**: Keep business logic in `services/`, data access in `repositories/`, and API definitions in `routes/`.
- **Naming**: Use snake_case for files and functions, PascalCase for classes.
- **Secrets/config**: Store in `.env` (not checked in by default).

## Examples
- To add a new API route: create a file in `app/api/routes/`, register it in `app/main.py`.
- To add a new model: define in `app/models/`, create corresponding schema in `app/schemas/`, and repository/service as needed.

## Notes
- The project may have non-standard filenames (e.g., `requirement.txt` instead of `requirements.txt`).
- Some folders (e.g., `output/`, `scripts/`) are present but not documented; check usage before modifying.

---

_If any section is unclear or missing, please provide feedback for further refinement._

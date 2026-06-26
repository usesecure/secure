# Language Stack Checks

Load this reference when reviewing a non-Next.js project, a multi-language repo, or an unfamiliar stack. Apply the invariant, not the framework names.

## Universal Translation

The same security bug appears with different syntax:

- auth/session: middleware, filters, guards, dependencies, claims, current user;
- authorization: roles, policies, gates, annotations, permission classes, decorators;
- object scope: tenant, organization, account, workspace, owner, project, company;
- mutation sink: ORM save/update/delete, SQL, repository methods, service methods, jobs;
- mass assignment: binding request bodies directly into models/entities/DTOs;
- public abuse: unauthenticated routes calling email, queues, AI, storage, payments, or webhooks.

Always trace from external input to sensitive sink.

## Python

Stacks: Django, DRF, Flask, FastAPI, Celery.

Inspect:

- `urls.py`, `views.py`, `serializers.py`, `permissions.py`, `dependencies.py`, routers, blueprints;
- DRF `permission_classes`, `get_queryset`, serializer fields, `perform_create/update`;
- FastAPI `Depends`, auth dependencies, Pydantic schemas, background tasks;
- Flask blueprints, decorators, `g`, session, request JSON, CORS;
- Celery tasks that run with broader authority than request initiators.

Common failures:

- queryset scoped in list but not retrieve/update/delete;
- serializer exposes `user`, `tenant`, `is_staff`, `role`, `status`, or `price`;
- `request.json`/`request.data` passed directly into model creation/update;
- `@csrf_exempt` or permissive CORS on cookie-auth routes.

## Java / Kotlin

Stacks: Spring MVC, Spring Boot, JAX-RS, Micronaut, Quarkus.

Inspect:

- `*Controller`, `*Resource`, `*Endpoint`, security config, filters, interceptors;
- `@PreAuthorize`, `@Secured`, `@RolesAllowed`, custom permission evaluators;
- repository methods and service-layer object scope;
- DTO/entity binding, `BeanUtils.copyProperties`, MapStruct mappings;
- multipart upload, signed URL, webhook, and async job handlers.

Common failures:

- controller has auth annotation but service/repository update lacks tenant scope;
- entity is bound directly from request body;
- `@CrossOrigin("*")` or broad CORS with credentials;
- method security disabled or not applied to internal service calls.

## .NET / C#

Stacks: ASP.NET Core MVC, Minimal APIs, Razor, Blazor server APIs, background services.

Inspect:

- controllers, Minimal API route maps, `Program.cs`, `Startup.cs`, policies, filters;
- `[Authorize]`, policy names, claims, tenant/organization resolution;
- EF Core queries, `SaveChanges`, repository methods;
- model binding, `TryUpdateModelAsync`, AutoMapper profiles;
- `IFormFile`, blob storage, signed URLs, webhooks, hosted services.

Common failures:

- `[Authorize]` used without object-level policy checks;
- route uses `FindAsync(id)` then updates/deletes without tenant scope;
- request DTO includes `Role`, `TenantId`, `OwnerId`, `Status`, `Price`, or `IsAdmin`;
- environment defaults enable permissive CORS or development auth.

## Go

Stacks: net/http, Gin, Echo, Fiber, Chi, gRPC.

Inspect:

- router setup, middleware ordering, handlers, interceptors;
- context user/claims extraction and authorization helpers;
- SQL/ORM calls, repository methods, transactions;
- JSON binding with `Bind`, `ShouldBind`, `Decode`, struct tags;
- goroutines/jobs that perform side effects after request auth.

Common failures:

- middleware not applied to one route group;
- `id` lookup lacks tenant/account predicate;
- struct binding allows role/status/owner fields;
- outbound URL/file inputs create SSRF or storage-key confusion.

## Ruby

Stacks: Rails, Sinatra, Sidekiq.

Inspect:

- `routes.rb`, controllers, policies, models, serializers, jobs;
- `before_action`, Devise, Pundit, CanCanCan;
- strong params, nested attributes, scopes, default scopes;
- ActiveStorage, signed IDs, direct uploads, public blob URLs;
- Sidekiq jobs and mailers.

Common failures:

- `permit!` or overly broad strong params;
- policy used in controller but not in service/job path;
- tenant scope applied in index but not show/update/destroy;
- ActiveStorage blobs exposed without ownership checks.

## PHP

Stacks: Laravel, Symfony, WordPress plugins, custom PHP.

Inspect:

- routes, controllers, middleware, policies, gates, form requests;
- Eloquent `$fillable`/`$guarded`, request validation, resource controllers;
- Symfony voters, security.yaml, param converters;
- file uploads, storage disks, signed routes, queues, mail, webhooks.

Common failures:

- mass assignment via `Model::create($request->all())`;
- `$guarded = []` on sensitive models;
- route group misses auth middleware;
- signed route checks URL signature but not object ownership.

## Rust

Stacks: Axum, Actix, Rocket, Warp.

Inspect:

- router composition, extractors, middleware/layers, guards;
- claims/session extraction, role/tenant checks;
- SQLx/Diesel queries and transaction boundaries;
- serde request structs and fields;
- async tasks and external calls.

Common failures:

- extractor validates identity but handler skips object authorization;
- request struct includes policy fields;
- route layer applied to one router branch but not another;
- storage keys or callback URLs are client-controlled.

## SQL / ORM Layer

Inspect direct data boundaries in every stack:

- `find(id)`, `findById`, `First`, `FindAsync`, `get_object_or_404`, `Model.find`;
- update/delete methods with only primary key predicates;
- raw SQL string interpolation;
- soft-delete, visibility, status, tenant, and owner filters;
- migrations that create permissive defaults.

Critical pattern:

```text
lookup by id only -> permission checked weakly or not at all -> update/delete/sign/export
```

Fix by scoping the lookup/update/delete at the database boundary and using canonical policy checks.

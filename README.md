# Keleya Skill-Check

## Backend

The task here is to finish the provided 'barebone' backend by implementing all endpoints and required functionality, and setting up the database following these requirements. The goal of this 'project' is to end up with a working REST API with CRUD endpoints for a simple user management, paired with authorization and authentication methods.

For the backend we are using two modern frameworks, [NestJS](https://docs.nestjs.com/) and [Prisma](https://www.prisma.io/docs/getting-started) running on Node 14. To make the database setup as simple as possible, we will use a SQlite DB. One part of this task will thus be, to familiarize yourself with the technology stack.

The repository as provided throws NotImplementedException() for the missing functions, as well as misses the data structures and database.

### Types

Data is being transferred between functions using Data Transfer Objects. This need to be implemented in accordance with the data model. Optionally, data validation should be implemented as well to assure that valid data is being sent into the application.

### Database

The database should follow this schema:
![backend schema](backend_schema.png)

Command lines:

- `npx prisma migrate dev` for migration
- `npx prisma db seed` for seeding

### Endpoints

- GET /user should query for users with these optional filtering parameters:
  - `limit` Limit the number of results returned
  - `offset` Skip the first n results
  - `updatedSince` Return only items which were updated since Date.
  - `id` An Array of id(s) to limit the query to
  - `name` a LIKE search for names
  - `credentials` include the related credentials in result
  - `email` search for matching email
- GET /user/:id should return one specific user with that id
- (public) POST /user should create a new user with credentials
- PATCH /user should update a user if it exists and should update credentials if they exist IF the user has not been deleted previously
- DELETE /user marks the user as deleted and also removes related credentials rows, but does NOT remove the user row itself
- (public) POST /user/authenticate authenticates the user with an email/password combination and returns a boolean
- (public) POST /user/token authenticates the user with an email/password combination and returns a JWT token
- (public) POST /user/validate validates a Bearer token sent via authorization header and returns a boolean

### Security

- Endpoints marked (public) should allow access without authorization
- Endpoints **not** marked (public) should check JWT tokens and map to users
- Health Check endpoints should be public and no JWT should be required
- Non-public endpoints called by Admin users should allow requests to modify all users, while regular users should locked into their own user - they are only allowed to work on their own user id
- Passwords need to be hashed and salted

### Testing

- If possible, unit tests should check the functionality of the various endpoints and services
- Alternatively, discuss why certain tests were not implemented, necessary or useful, or suggest a test environment

### Extra

- Discuss improvements to the data models or endpoints
- Feel free to suggest other solutions to implement similar projects (but for this skill check, do use the given tech stack as provided here)

### How to do the skill check

- Fork this repository
- Make modifications as you see fit
- Add all your notes into this readme
- Send us the link to your fork
- Tell us how long it took you to get the repository to the state you sent us - remember: it's ok to take time if it's done properly.
- Import Hiring Backend Test.postman_collection.json into the latest Postman client and run the collection tests. Depending on how you seed your database, some tests may need to be adjusted for ids. Please take a screenshot of the results like this one:
- ![postman_tests.png](postman_tests.png)
- Send us this screenshot as well as the export of your postman tests.
- the following should run without errors:
```
yarn
npx migrate reset
yarn test
```
### Your Notes Below Here

### Improvements

1. User delete endpoint can have the id passed as path parameter rather than request body. Matter of fact, in OpenAPI / Swagger Documentation you can't even document a `DELETE` API with body. Only path, query params are allowed!
2. JWT related methods are inside `user.service`. This is really weird because it violates Single Responsibility, Open for Extension and Closed for Mutation in SOLID principles. In future, if we want to sign and pass as reset email token in JWT form, this design is really inefficient.
3. There is no difference between `authenticate` and `token` endpoint. The user should be granted their token in the authenticate API iteslf.
4. Also, refresh token API is missing
5. Containerize entire deployment
   - Ingress for service discovery
   - Redis container for caching cachable GET requests
   - Database of choice. Since they are on same network, they are all addressable by respective service names
   - Database init container to set up app specific schema and master data
  
  ![system-design](system-diagram.jpg)

### Disclaimer
1. User delete doesn't work. Foreign key violation in delete method. I can't seem to fix it. It's something related to my schema definition (probably)
2. The codebase is not entirely mine. Since the repo is public I can see all the forks of this repo and see the submissions from other candidates. I selected one after realizing that I too would to exactly likewise and made changes that I think are relevant.
3. Took me 6 hours to set it up since I cloned from a existing codebase
4. I already took a long break to start on this project due to various reasons, and also commited that I'll submit it on Monday. Hence all the postman collections weren't tested
5. Prisma is cool. Much more easier than Sequelize ORM

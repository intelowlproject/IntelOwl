# IntelOwl - frontend

Built with [@certego/certego-ui](https://github.com/certego/certego-ui).

## Design thesis

- Re-usable components/hooks/stores that other projects can also benefit from should be added to [certego-ui](https://github.com/certego/certego-ui) package.
- IntelOwl specific:
  - components should be added to `src/components/common`.
  - general hooks should be added to `src/hooks`.
  - zustand stores hooks should be added to `src/stores`.

## Directory Structure

```text
public/                                   public static assets
|- icons/                                 icons/favicon
|- index.html/                            root HTML file
src/                                      source code
|- components/                            pages and components
|  |- auth/                               `authentication` (login, logout, OAuth pages)
|  |- common/                             small re-usable components
|  |- dashboard/                          dashboard page and charts
|  |- home/                               landing/home page
|  |- jobs/                               `api_app`
|  |  |- result/                          JobResult.jsx
|  |  |- table/                           JobsTable.jsx
|  |- me/
|  |  |- organization/                    `certego_saas.apps.organization`
|  |  |- sessions/                        durin (sessions management)
|  |- misc/
|  |  |- notification/                    `certego_saas.apps.notifications`
|  |- plugins/                            `api_app.analyzers_manager`, `api_app.connectors_manager`
|  |- scan/                               new scan/job
|  |- Routes.jsx                          lazy route-component mappings
|- constants/                             constant values
|  |- api.js                              API URLs
|  |- environment.js                      environment variables
|  |- index.js                            intelowl specific constants
|- hooks/                                 react hooks
|- layouts/                               header, main, footer containers
|- stores/                                zustand stores hooks
|- styles/                                scss files
|- utils/                                 utility functions
|- wrappers/                              Higher-Order components
|- App.jsx                                App component
|- index.jsx                              Root JS file (ReactDOM renderer)
```

## Local Development Environment

The frontend inside the docker containers does not hot-reload, so
you need to use `CRA dev server` on your host machine to serve pages when doing development on the frontend, using docker nginx only as API source.

- Start IntelOwl containers (see [docs](https://intelowl.readthedocs.io/en/latest/Installation.html)). Original dockerized app is accessible on `http://localhost:80`

- If you have not `node-js` installed, you have to do that. Follow the guide [here](https://www.digitalocean.com/community/tutorials/how-to-install-node-js-on-ubuntu-20-04). We tested this with NodeJS >=16.6

- Install npm packages locally

```bash
cd ./frontend && npm install
```

- Start CRA dev server:

```bash
npm start
```

- Now you can access the auto-reloading frontend on `http://localhost:3000`. It acts as proxy for API requests to original app web server.

- JS app main configs are available in `package.json`.

- (optional) Use local build of `certego-ui` package so it can also hot-reload. This is useful when you want to make changes in certego-ui and rapidly test them with IntelOwl. Refer [here](https://github.com/certego/certego-ui#use-local-build-of-certego-ui-with-hot-reload-for-faster-development) for setup instructions.

## Miscellaneous

### Dependabot

We have dependabot enabled for the React.js frontend application. The updates are scheduled for once a week.

### External Docs

- [Create React App documentation](https://facebook.github.io/create-react-app/docs/getting-started).
- [React documentation](https://reactjs.org/).

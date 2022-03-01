# IntelOwl - frontend

Built with [@certego/certego-ui](https://github.com/certego/certego-ui).

## Design thesis

- Re-usable components/hooks/stores that other projects can also benefit from should be added to [certego-ui](https://github.com/certego/certego-ui) package.
- IntelOwl specific:
  - components should be added to `src/components/common`.
  - general hooks should be added to `src/hooks`.
  - zustand stores hooks should be added to `src/stores`.

## Directory Structure

```
public/                                   public static assets
|- icons/                                 icons/favicon
|- index.html/                            root HTML file
src/                                      source code
|- components/                            pages and components
|  |- auth/                               `api_app.auth` (login, logout pages)
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

The frontend inside the docker containers does not hot-reload so
you need to start a npm dev server on your host machine when doing development on the frontend.

- (required) Inject `env.js` using a symbolic link,

```bash
$/home/user/IntelOwl: ln -s docker/env.js frontend/public/env.js
```

- (optional) Use local build of `certego-ui` package so it can also hot-reload. This is useful when you want to make changes in certego-ui and rapidly test them with IntelOwl. Refer [here](https://github.com/certego/certego-ui#use-local-build-of-certego-ui-with-hot-reload-for-faster-development) for setup instructions.

## Miscellaneous

### Why do we need the `@craco/craco` package ?

For 2 reasons:

- Required for using [@welldone-software/why-did-you-render](https://github.com/welldone-software/why-did-you-render) package which helps us identify whether the pure components are actually working as intended or not.
- Required for using local build of `certego-ui` package. If you see line 38 onwards in the `craco.config.js` file there exists some package aliases to avoid conflicts in dependencies that are common in IntelOwl frontend and certego-ui.

### Dependabot

We have depandabot enabled for the React.js frontend application. The updates are scheduled for once a week.

### External Docs

- [Create React App documentation](https://facebook.github.io/create-react-app/docs/getting-started).
- [React documentation](https://reactjs.org/).

# DD2391-Project-Group7

Problem statement,
Reference,
Documentation of project,
Documentation on testing the project

## How to use

To run this lab, you need to have Docker installed. You can install it [here](https://docs.docker.com/engine/install/), or you can install Docker Desktop.

Once you have cloned the repository to your computer, use `docker compose` to start the containers.

```bash
docker compose up --build
```

The `--build` flag makes sure all Docker images are built before running them.

Once running, the log output from all three containers (`firewall`, `client` and `server` will be logged in your console).

You can now open another terminal to attach this terminal to a shell of the client image.

```bash
docker compose exec -it client ash
```

You know have a shell inside the `client` container. If you try to ping stuff from here, you should see your packets being processed by the firewall in the first terminal.

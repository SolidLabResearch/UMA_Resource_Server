import { ResourceServer } from "./ResourceServer";

const authServer = "http://localhost:4000/uma"
const port = 5656
const r = new ResourceServer(authServer, port)
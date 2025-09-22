const schema = {
    namespace: "example",
    name: "Ping Test API",
    description: "A simple schema that responds with pong",
    docs: [],
    tags: [],
    flowMCP: "1.2.0",
    root: "https://localhost",
    requiredServerParams: [],
    headers: {},
    routes: {
        ping: {
            requestMethod: "GET",
            description: "Returns pong for ping test",
            route: "/ping",
            parameters: [],
            tests: [],
            modifiers: [
                { phase: "execute", handlerName: "respondWithPong" }
            ]
        }
    },
    handlers: {
        respondWithPong: async( { struct, payload } ) => {
            struct.data = { message: 'pong' }
            struct.status = true
            return { struct, payload }
        }
    }
}


export { schema }
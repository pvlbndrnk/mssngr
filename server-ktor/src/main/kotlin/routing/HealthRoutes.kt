package com.pvlbndrnk.routing

import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.health() {
    get("/health") {
        call.respond(HttpStatusCode.OK)
    }
}

package com.pvlbndrnk.chat.di

import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.SIMPLE

actual val httpLogger: Logger = Logger.SIMPLE
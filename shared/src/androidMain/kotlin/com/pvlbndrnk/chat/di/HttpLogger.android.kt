package com.pvlbndrnk.chat.di

import io.ktor.client.plugins.logging.ANDROID
import io.ktor.client.plugins.logging.Logger

actual val httpLogger: Logger = Logger.ANDROID
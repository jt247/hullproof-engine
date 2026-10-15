plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "com.acme.notes"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.acme.notes"
        minSdk = 24
        targetSdk = 34
    }
}

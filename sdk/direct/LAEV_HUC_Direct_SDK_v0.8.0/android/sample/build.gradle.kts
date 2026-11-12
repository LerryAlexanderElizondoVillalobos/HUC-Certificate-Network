plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.bylaev.hucsample"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.bylaev.hucsample"
        minSdk = 26
        targetSdk = 35
        versionCode = 8
        versionName = "0.8.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    // OSGi bundle metadata is not needed at Android runtime. Bouncy Castle
    // ships the same versioned manifest in multiple JARs, which otherwise
    // makes the APK Java-resource merge fail.
    packaging {
        resources.excludes += "/META-INF/versions/9/OSGI-INF/MANIFEST.MF"
    }
}

dependencies {
    implementation(project(":huc-direct"))
    implementation("androidx.core:core-ktx:1.15.0")
}

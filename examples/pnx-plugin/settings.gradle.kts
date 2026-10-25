rootProject.name = "BedrockPresencePlugin"

dependencyResolutionManagement {
    @Suppress("UnstableApiUsage")
    repositories {
        mavenCentral()
        // PNX SDK
        maven("https://repo.powernukkitx.org/releases")
        maven("https://repo.opencollab.dev/maven-releases")
        maven("https://repo.opencollab.dev/maven-snapshots")
        maven("https://www.jitpack.io")
    }
}

plugins {
    java
}

group = "net.troporia"
version = "1.0.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

dependencies {
    // PowerNukkitX API (includes Gson and the Bedrock protocol classes),
    // provided at runtime by the server, not bundled.
    compileOnly("org.powernukkitx:server:nightly-SNAPSHOT")
}

tasks.jar {
    archiveBaseName.set("BedrockPresence")
}

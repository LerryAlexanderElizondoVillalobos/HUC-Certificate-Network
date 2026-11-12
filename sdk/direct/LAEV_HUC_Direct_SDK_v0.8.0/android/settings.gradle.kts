pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }
rootProject.name = "LAEV-HUC-Direct-Android"
include(":huc-direct", ":sample")
project(":huc-direct").projectDir = file("huc-direct")
project(":sample").projectDir = file("sample")

#!/bin/sh
# Uses optional project-local tools. A normal JDK/Android SDK installation also works.
set -eu
SAT_PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -z "${JAVA_HOME:-}" ] && [ -x "$SAT_PROJECT_ROOT/.tools/java17/bin/java" ]; then
    JAVA_HOME="$SAT_PROJECT_ROOT/.tools/java17"
    export JAVA_HOME
fi
if [ -z "${ANDROID_HOME:-}" ] && [ -d "$SAT_PROJECT_ROOT/.tools/android-sdk/platforms/android-35" ]; then
    ANDROID_HOME="$SAT_PROJECT_ROOT/.tools/android-sdk"
    export ANDROID_HOME
fi
GRADLE_USER_HOME=${GRADLE_USER_HOME:-"$SAT_PROJECT_ROOT/.gradle-user-home"}
ANDROID_USER_HOME=${ANDROID_USER_HOME:-"$SAT_PROJECT_ROOT/.tools/android-user"}
export GRADLE_USER_HOME ANDROID_USER_HOME
cd "$SAT_PROJECT_ROOT"
exec sh ./gradlew "$@"

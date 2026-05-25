# app3 - Уязвимое Android приложение для тестирования анализаторов безопасности

**Package:** com.masttest.vuln03  
**Kotlin:** 2.3.0  
**Gradle:** 9.2.1  
**JDK:** 21  
**Target SDK:** 35 (Android 15)

## Назначение

Приложение разработано специально для тестирования статических и динамических анализаторов безопасности на предмет обнаружения уязвимостей, соответствующих OWASP Mobile Top 10.

## Архитектура приложения

```
app/
├── src/main/
│   ├── java/com/masttest/vuln03/
│   │   ├── MainActivity.kt              # Главная активность
│   │   ├── VulnerableService1.kt        # Сервис 1: Insecure Data Storage
│   │   ├── VulnerableService2.kt        # Сервис 2: Improper Credential Usage (KeyChain)
│   │   ├── VulnerableService3.kt        # Сервис 3: Improper Credential Usage (Keystore)
│   │   └── SecurityUtils.kt             # Утилиты безопасности (с уязвимостями)
│   └── res/
│       ├── layout/
│       │   └── activity_main.xml        # UI главной активности
│       ├── values/
│       │   ├── strings.xml              # Строковые ресурсы
│       │   └── themes.xml               # Темы приложения
│       └── xml/
│           └── backup_rules.xml         # Правила резервного копирования
└── build.gradle.kts
```

## Заложенные уязвимости

---

### 🔴 Уязвимость #1: M9 - Insecure Data Storage

**Сервис:** `VulnerableService1.kt`  
**OWASP:** M9: Insecure Data Storage  
**Суть:** Использование доступного на запись хранилища ключей с экспортом ключевого материала

#### Описание уязвимости:
- Ключи хранятся в world-writable директории (`MODE_WORLD_WRITEABLE`)
- Реализована возможность экспорта ключевого материала в незашифрованном виде
- Ключи сохраняются в SharedPreferences без шифрования
- Отсутствует защита от извлечения ключей через root-доступ

#### Местоположение в коде:
- **Файл:** `app/src/main/java/com/masttest/vuln03/VulnerableService1.kt`
- **Строки с уязвимостями:**
  - Строка ~45: `Context.MODE_WORLD_WRITEABLE` - создание world-writable хранилища
  - Строка ~60: `keyGenerator.keySpecs` - экспорт ключевого материала
  - Строка ~75: Сохранение ключа в SharedPreferences без шифрования
  - Строка ~90: Чтение ключа из файла без проверки целостности

#### Как найти в коде:
```kotlin
// УЯЗВИМОСТЬ: MODE_WORLD_WRITEABLE позволяет любому приложению записать данные
getSharedPreferences("keys", Context.MODE_WORLD_WRITEABLE)

// УЯЗВИМОСТЬ: Экспорт приватного ключа в байтовый массив
val keySpec = keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec::class.java)
val exportedKey = keySpec.encoded

// УЯЗВИМОСТЬ: Сохранение ключа в plain text
sharedPrefs.edit().putString("secret_key", Base64.encodeToString(keyBytes, Base64.DEFAULT))
```

---

### 🔴 Уязвимость #2: M1 - Improper Credential Usage (KeyChain со слабым паролем)

**Сервис:** `VulnerableService2.kt`  
**OWASP:** M1: Improper Credential Usage  
**Суть:** Использование Android KeyChain с приватными ключами, защищёнными слабым паролем

#### Описание уязвимости:
- Слабый пароль "1234" используется для защиты ключей KeyChain
- Пароль хранится в коде приложения (hardcoded)
- Ключи доступны на чтение другим приложениям через MODE_WORLD_READABLE
- Отсутствие политики сложности пароля
- Пароль сохраняется в SharedPreferences в открытом виде

#### Местоположение в коде:
- **Файл:** `app/src/main/java/com/masttest/vuln03/VulnerableService2.kt`
- **Строки с уязвимостями:**
  - Строка ~30: `const val WEAK_PASSWORD = "1234"` - слабый hardcoded пароль
  - Строка ~55: Сохранение пароля в SharedPreferences с MODE_WORLD_READABLE
  - Строка ~70: Использование слабого пароля для KeyChain
  - Строка ~85: Отсутствие проверки сложности пароля

#### Как найти в коде:
```kotlin
// УЯЗВИМОСТЬ: Слабый hardcoded пароль
companion object {
    const val WEAK_PASSWORD = "1234"
}

// УЯЗВИМОСТЬ: Режим WORLD_READABLE делает данные доступными для чтения
getSharedPreferences("credentials", Context.MODE_WORLD_READABLE)

// УЯЗВИМОСТЬ: Пароль хранится в открытом виде
sharedPrefs.edit().putString("password", WEAK_PASSWORD).apply()

// УЯЗВИМОСТЬ: Использование слабого пароля для KeyChain
keyChainAlias = KeyChain.createPrivateKeyAlias(WEAK_PASSWORD)
```

---

### 🔴 Уязвимость #3: M1 - Improper Credential Usage (Hardware-Backed Keystore со слабым PIN)

**Сервис:** `VulnerableService3.kt`  
**OWASP:** M1: Improper Credential Usage  
**Суть:** Использование Hardware-Backed Keystore со слабым PIN-кодом и отсутствием аутентификации

#### Описание уязвимости:
- Слабый 4-значный PIN "0000" для доступа к аппаратному хранилищу
- Отключена обязательная аутентификация пользователя (`setUserAuthenticationRequired(false)`)
- Возможность обхода проверки PIN через модификацию флага
- Ключи генерируются без требования разблокированного устройства
- Отсутствие ограничения на количество попыток ввода PIN

#### Местоположение в коде:
- **Файл:** `app/src/main/java/com/masttest/vuln03/VulnerableService3.kt`
- **Строки с уязвимостями:**
  - Строка ~35: `const val WEAK_PIN = "0000"` - слабый PIN
  - Строка ~60: `.setUserAuthenticationRequired(false)` - отключение аутентификации
  - Строка ~75: Обход проверки PIN при наличии флага debug
  - Строка ~95: Отсутствие rate limiting для попыток ввода PIN

#### Как найти в коде:
```kotlin
// УЯЗВИМОСТЬ: Слабый 4-значный PIN
companion object {
    const val WEAK_PIN = "0000"
}

// УЯЗВИМОСТЬ: Отключение обязательной аутентификации пользователя
val keyGenParameterSpec = KeyGenParameterSpec.Builder(alias, purposes)
    .setUserAuthenticationRequired(false)  // Критическая уязвимость!
    .build()

// УЯЗВИМОСТЬ: Обход проверки PIN
if (BuildConfig.DEBUG || pin == WEAK_PIN) {
    return true  // Доступ разрешён без должной проверки
}

// УЯЗВИМОСТЬ: Нет ограничения попыток
fun verifyPin(inputPin: String): Boolean {
    return inputPin == WEAK_PIN  // Бесконечные попытки возможны
}
```

---

## Дополнительные уязвимости в SecurityUtils.kt

**Файл:** `app/src/main/java/com/masttest/vuln03/SecurityUtils.kt`

### Уязвимости:
1. **Hardcoded криптографические ключи** - строка ~25
2. **Слабый алгоритм шифрования (DES)** - строка ~40
3. **Отсутствие проверки сертификатов SSL** - строка ~60
4. **Логирование чувствительных данных** - строка ~80

```kotlin
// УЯЗВИМОСТЬ: Hardcoded ключ шифрования
private const val HARDCODED_KEY = "MySecretKey12345"

// УЯЗВИМОСТЬ: Использование устаревшего DES
Cipher.getInstance("DES/ECB/PKCS5Padding")

// УЯЗВИМОСТЬ: TrustAllManager принимает все сертификаты
object : X509TrustManager() {
    override fun checkServerTrusted(chain: Any?, authType: String?) {}
}

// УЯЗВИМОСТЬ: Логирование паролей и ключей
Log.d("DEBUG", "Password: $password, Key: $secretKey")
```

---

## Сводная таблица уязвимостей

| № | Сервис | Тип уязвимости | OWASP Category | Файл | Критичность |
|---|--------|----------------|----------------|------|-------------|
| 1 | VulnerableService1 | World-writable хранилище + экспорт ключей | M9: Insecure Data Storage | VulnerableService1.kt | HIGH |
| 2 | VulnerableService2 | KeyChain со слабым паролем | M1: Improper Credential Usage | VulnerableService2.kt | HIGH |
| 3 | VulnerableService3 | Hardware Keystore со слабым PIN | M1: Improper Credential Usage | VulnerableService3.kt | CRITICAL |
| 4 | SecurityUtils | Hardcoded ключи, слабый cipher | M9: Insecure Data Storage | SecurityUtils.kt | MEDIUM |
| 5 | SecurityUtils | SSL Pinning bypass | M3: Insecure Communication | SecurityUtils.kt | HIGH |
| 6 | SecurityUtils | Логирование секретов | M9: Insecure Data Storage | SecurityUtils.kt | MEDIUM |

---

## Сборка проекта

```bash
# Сборка debug APK
./gradlew assembleDebug

# Сборка release APK
./gradlew assembleRelease

# Запуск тестов
./gradlew test

# Проверка линтером
./gradlew lint
```

## Требования к среде сборки

- **JDK:** 21
- **Gradle:** 9.2.1
- **Kotlin:** 2.3.0
- **Android Gradle Plugin:** 8.7.0
- **Min SDK:** 26
- **Target SDK:** 35

## Ожидаемые результаты анализа

Анализаторы безопасности должны обнаружить:

1. **Статический анализ:**
   - Использование `MODE_WORLD_WRITEABLE` и `MODE_WORLD_READABLE`
   - Hardcoded пароли и ключи в коде
   - Отключение `setUserAuthenticationRequired`
   - Слабые криптографические алгоритмы (DES, ECB)
   - TrustAllManager для SSL

2. **Динамический анализ:**
   - Возможность чтения SharedPreferences из других приложений
   - Экспорт ключей в незашифрованном виде
   - Обход аутентификации при слабом PIN
   - Логирование чувствительных данных в Logcat

---

## Предупреждение

⚠️ **Данное приложение содержит преднамеренные уязвимости безопасности и НЕ ДОЛЖНО использоваться в production среде!**

Приложение предназначено исключительно для:
- Тестирования анализаторов безопасности
- Образовательных целей
- Исследования уязвимостей мобильных приложений

---

## Лицензия

Только для внутреннего использования в целях тестирования безопасности.

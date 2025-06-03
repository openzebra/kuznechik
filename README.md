# Кузнечик

Библиотека для шифрования и дешифрования данных по алгоритму «Кузнечик» (ГОСТ Р 34.12-2015). Реализует режимы шифрования ECB, CBC, CFB, CTR, OFB и MAC. Написана на TypeScript, обеспечивает высокую производительность и типобезопасность.

## Возможности
- Поддержка всех стандартных режимов шифрования: ECB, CBC, CFB, CTR, OFB.
- Вычисление имитовставки (MAC).
- Работа с 256-битными ключами и 128-битными блоками.
- Модульная структура с поддержкой ESM и CJS.
- Полная типизация для TypeScript.

## Установка
```bash
npm install kuznechik
```

## Использование
Пример шифрования и дешифрования в режиме ECB:

```ts
import { KeyStore, AlgEcb } from 'kuznechik';

const masterKey = new Uint8Array([
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
]);

const data = new Uint8Array([
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
  0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
]);

const keyStore = new KeyStore();
keyStore.setMasterKey(masterKey);

const alg = new AlgEcb(keyStore);
const encrypted = alg.encrypt(data);
const decrypted = alg.decrypt(encrypted);

console.log('Зашифрованные данные:', encrypted);
console.log('Расшифрованные данные:', decrypted);
```

## Сборка проекта
1. Установите зависимости:
   ```bash
   npm install
   ```
2. Соберите библиотеку:
   ```bash
   npm run build
   ```
3. Выходные файлы будут в папке `dist`.

## Тестирование
Для запуска тестов используйте:
```bash
npm test
```

## Структура проекта
- `src/` — исходный код библиотеки.
- `__tests__/` — тесты с использованием Vitest.
- `dist/` — собранные файлы (CJS, ESM, типы).
- `index.ts` — точка входа.

## Лицензия
MIT

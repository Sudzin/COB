# Log Analyzer

Веб-анализатор системных журналов (syslog): находит перебор паролей (brute-force / IP spraying), строит статистику по IP и формирует отчёт в PDF.
Проект начался как лабораторная работа №1 «Выявление аномалий и инцидентов ИБ в системных журналах».

## Возможности

- чтение всех `.txt` / `.log` файлов из папки `logs/`; битые, пустые и не-UTF-8 файлы не ломают работу;
- разбор строк syslog регулярными выражениями: время, узел, служба, пользователь, IP, порт;
- подсчёт неудачных попыток по каждому IP, настраиваемый **порог** и **временное окно** (в минутах или `ЧЧ:ММ:СС`);
- фильтры по статусу, IP, пользователю, службе, узлу и поиск по тексту;
- сводная таблица результатов тестирования (ожидалось / факт);
- экспорт отчёта в PDF (через печать браузера).

## Быстрый старт

Нужен [Node.js](https://nodejs.org) версии 18.11 или новее. Зависимостей нет, `npm install` не требуется.

```bash
# 1. положи тестовые логи в папку logs/ (L1.txt, L2.txt, ...)
# 2. запусти
npm start
# 3. открой http://localhost:3000
```

Другие команды:

| Команда | Что делает |
| --- | --- |
| `npm run dev` | запуск с автоперезапуском сервера при изменении файлов |
| `npm test` | запуск тестов (`node:test`, без внешних библиотек) |

Настройки через переменные окружения:

| Переменная | По умолчанию | Описание |
| --- | --- | --- |
| `PORT` | `3000` | порт сервера |
| `LOGS_DIR` | `./logs` | папка с логами |

В PowerShell: `$env:PORT=8080; npm start`.

## ЛР №2: анализ сетевого трафика

Вкладка **«Трафик»** анализирует захваты `.pcap` из папки `pcaps/` (`PCAPS_DIR`): разбирает пакеты (IPv4 + TCP/UDP/ICMP, остальное игнорируется), собирает потоки по пятёрке `(IP_src, IP_dst, Port_src, Port_dst, Protocol)`, считает пакеты, байты, длительность, PPS/BPS, долю SYN, средний размер и счётчики TCP-флагов (SYN/ACK/RST/FIN/PSH).

- **Симметричные потоки:** A→B и B→A — один поток; «инициатор» — отправитель первого пакета, направления считаются отдельно (`→` / `←`).
- **Классификация** (пороги — `TRAFFIC` в `src/config.js`): легитимный трафик, сканирование портов (много портов одного узла, по 1–2 пакета без ACK), SYN-флуд (SYN без ACK на один порт от многих источников), аномалии ICMP (echo на broadcast, крупные пакеты, нестандартные типы, высокая частота).
- **Графики** (SVG, без библиотек): гистограмма размеров пакетов (лог. шкала), протоколы, TCP-флаги, таймлайн, топ-10 потоков. Кнопка «Экспорт в PDF» использует ту же печатную функцию, что и отчёты по логам.
- PPS/BPS не считаются для потоков из одного пакета и короче 1 мс (в таблице «—»).
- Форматы: `.pcap` (Ethernet, Raw IP, Linux cooked, BSD loopback). `.pcapng` не поддерживается — сохраните как pcap.

### Живой захват и тестовый трафик

Нужен `dumpcap` (идёт с Wireshark/Npcap) или `tcpdump`; на Windows — Npcap.

```bash
npm run capture -- --list                              # список интерфейсов
npm run capture -- --iface "Ethernet 5" --count 500    # захват в pcaps/capture_*.pcap
npm run capture -- --iface 4 --time 30                 # или не дольше 30 секунд
npm run udp-burst -- --host 127.0.0.1 --count 5000     # пустые UDP, только localhost / частная сеть
```

Сценарии п. 8: `ping -n 20 8.8.8.8` (Linux/macOS: `ping -c 20 8.8.8.8`); `curl` к нескольким сайтам одновременно; `udp-burst`. Для loopback на Windows при установке Npcap включите «Support loopback traffic». Образец для проверки классификации: `pcaps/lab2_test_traffic.pcap`.

## Структура проекта

```
log-analyzer/
├── package.json
├── README.md
├── ROADMAP.md
├── .gitignore
├── logs/                          # входные логи (.txt / .log)
├── pcaps/                         # захваты трафика (.pcap) для вкладки «Трафик»
├── tools/                         # capture.js (живой захват), udp-burst.js (генератор UDP)
├── tests/                         # тесты ядра
│   ├── parseDetailedLogLine.test.js
│   └── scanLogsDirectory.test.js
├── src/                           # бэкенд (Node.js, CommonJS)
│   ├── config.js                  # порт, пути, год лога, расширения
│   ├── core/                      # логика анализа, не знает про HTTP
│   │   ├── patterns.js            # все регулярные выражения
│   │   ├── readLogFileSafely.js   # чтение файла + обработка ошибок
│   │   ├── parseDetailedLogLine.js# разбор одной строки на поля
│   │   ├── analyzeLog.js          # разбор файла: строки, время, длительность
│   │   ├── scanLogsDirectory.js   # обход папки logs/
│   │   ├── helpers/formatProto.js
│   │   └── pcap/                  # ЛР №2: parsePcap, parsePacket, normalizeFlowKey,
│   │                              # aggregateFlows, computeFlowMetrics, classifyFlows, analyzePcap
│   └── server/                    # HTTP-слой
│       ├── index.js               # точка входа
│       ├── createServer.js        # маршрутизация
│       ├── routes/
│       │   ├── scanRoute.js       # GET /api/scan
│       │   └── staticRoute.js     # раздача public/
│       └── utils/                 # sendJson, sendText, getMimeType
└── public/                        # фронтенд (ES-модули, без сборки)
    ├── index.html
    ├── css/                       # base, layout, file-list, controls, filters,
    │                              # log-table, stats, modal, print
    └── js/
        ├── main.js                # точка входа: обработчики событий
        ├── state.js               # общее состояние (store)
        ├── constants.js
        ├── api/loadData.js        # запрос /api/scan
        ├── analysis/              # чистые функции: окно, подсчёт сбоев по IP
        ├── filters/               # панель фильтров и описание полей
        ├── render/                # отрисовка таблиц, списка, статистики
        ├── ui/                    # вкладки, модалка, валидация параметров
        ├── export/exportToPdf.js  # экспорт отчёта
        ├── config/expected.js     # эталонные результаты для таблицы тестирования
        └── utils/                 # esc, pad2
```

## Как устроено

Три слоя, зависимости идут только сверху вниз:

1. **`src/core`** — чистая логика: принимает путь или текст, возвращает объекты. Её можно запускать без сервера (например, из будущего CLI) и тестировать отдельно.
2. **`src/server`** — тонкая обёртка: отдаёт результат `core` по `GET /api/scan` и статику из `public/`.
3. **`public`** — интерфейс. Получает готовые разобранные строки и сам считает пороги, окна и фильтры в браузере.

Правило проекта: **одна функция — один файл**, файл называется как функция.

## API

`GET /api/traffic` — анализ всех `.pcap` из `pcaps/` (потоки, категории, инциденты, данные для графиков).

`GET /api/scan` возвращает:

```json
{
  "status": "SUCCESS",
  "files": [
    {
      "fileName": "L1.txt",
      "status": "OK",
      "totalLines": 120,
      "rows": [{ "lineNum": 1, "ip": "203.0.113.45", "opStatus": "Failed", "isFailure": true }],
      "minTime": "2026-10-13T08:09:50.000Z",
      "maxTime": "2026-10-13T08:41:12.000Z",
      "totalDurationMin": 32
    }
  ]
}
```

`status` бывает `SUCCESS`, `DIR_NOT_FOUND` или `DIR_EMPTY`; у файла — `OK` или `CORRUPTED` (тогда есть поле `error`).

## Как добавлять новое

- **Новый фильтр**: описать поле в `public/js/filters/filterFields.js` и добавить в список в `filterBars.js`.
- **Новый тип строки лога** (например, `Connection closed`): добавить регулярное выражение в `src/core/patterns.js` и ветку в `parseDetailedLogLine.js`.
- **Новый формат экспорта**: файл в `public/js/export/`, подключить в `main.js`.
- **Новый эталон для таблицы тестирования**: запись в `public/js/config/expected.js`.

## Известные ограничения

- В syslog нет года, он задан константой `LOG_YEAR` в `src/config.js`.
- Эталонные результаты в `expected.js` привязаны к именам `L1.txt`–`L5.txt`.

Дальнейшие планы — в [ROADMAP.md](ROADMAP.md).

# Kaigen Tox Core

Kaigen Tox Core is the Tox protocol core library maintained for the Kaigen
messenger. This fork incorporates the accepted update to TokTok/c-toxcore
`v0.2.24-rc.2` at commit `e033325ac3472d571274ec70fdb5a220a22b01bc`, with
Kaigen security, resource-bounding, and reliability changes preserved.
See [UPSTREAM.md](UPSTREAM.md) for the exact source lineage and change scope.

The library remains GPL-3.0-or-later. Original copyright, contributor history,
third-party notices, and licenses are preserved.

## Зачем Kaigen поддерживает собственный форк c-toxcore

Kaigen использует `c-toxcore` как сетевое ядро Tox. Собственный форк нужен не
для создания несовместимого варианта протокола, а для поддержки конкретной,
проверяемой версии библиотеки с исправлениями безопасности и надёжности.

Основные причины:

- часть проблем находилась внутри `c-toxcore` и не могла быть полноценно
  устранена на уровне приложения;
- Kaigen должен точно контролировать исходный код сетевого ядра, попадающий в
  релиз;
- исправления должны выпускаться по графику Kaigen, без обязательного ожидания
  нового upstream-релиза;
- для каждой сборки нужна воспроизводимая цепочка происхождения:
  upstream-коммит, набор патчей, итоговое дерево исходников и хеши;
- обновление upstream проводится управляемо: изменения анализируются, наши
  исправления переносятся, после чего повторяются проверки совместимости.

Перенос TokTok/c-toxcore `v0.2.24-rc.2`, commit
`e033325ac3472d571274ec70fdb5a220a22b01bc`, принят для форка Kaigen.
Сохранены исправления Kaigen из базового коммита
`b89934a6c152e5645697ee2974c9a5859855ad7c`, авторство исходного проекта и
лицензия GPL-3.0-or-later. Точная история происхождения — в
[UPSTREAM.md](UPSTREAM.md).

Обновление upstream добавляет проверку соответствия ключей при групповом
handshake, исправляет Windows LAN discovery, разбор IP/port, интервалы групповых
объявлений и обработку ошибочных RTP/MSI пакетов. Описанные ниже шесть защитных
изменений Kaigen сохранены; они не являются полным списком исправлений upstream.

### Какие проблемы были устранены

В ходе анализа были подтверждены шесть проблем среднего уровня серьёзности.
Пять из них относились к отказу в обслуживании: злоумышленник мог пытаться
перегрузить процессор, исчерпать память или задержать обработку остальных
соединений. Одна проблема затрагивала безопасность нативной памяти и поэтому
теоретически могла иметь более тяжёлые последствия.

#### 1. Ошибка обработки очень больших размеров в toxencryptsave

Функции шифрования профиля принимали размер типа `size_t`, но при выделении
временного буфера могли преобразовать его в более узкий 32-битный тип. В
результате для чрезвычайно большого значения могла быть выделена меньшая
область памяти, чем требовалось последующим операциям.

**Возможные последствия:** выход за границы буфера, повреждение памяти и
аварийное завершение процесса.

**Связь с RCE:** это единственная из шести находок, которая теоретически могла
создать предпосылку для выполнения произвольного кода. Повреждение памяти в
нативной C-библиотеке иногда удаётся превратить в RCE. Однако в ходе аудита
работоспособный RCE-эксплойт не создавался и возможность удалённой эксплуатации
через обычный сетевой пакет Tox не была доказана. Проблема находилась в API
обработки переданного вызывающей стороной большого буфера — прежде всего в
сценариях импорта или шифрования локальных данных.

В форке добавлена проверяемая арифметика. Непредставимые размеры и переполнения
отклоняются до выделения памяти, копирования или криптографической операции.

#### 2. Неограниченный рост состояния групповых объявлений

Обработка групповых объявлений могла создавать новую внутреннюю запись для
уникального идентификатора чата до завершения необходимой проверки. Ограничение
числа участников одного чата существовало, но общего предела количества таких
чатов не было.

**Возможные последствия:** постепенное увеличение потребления памяти и нагрузки
на процессор при отправке большого количества запросов с разными
идентификаторами.

**Связь с RCE:** не обнаружена. Это удалённый отказ в обслуживании при доступном
прямом UDP-маршруте, а не повреждение памяти.

Теперь внутреннее состояние изменяется только после корректной проверки.
Устаревшие записи удаляются, а число одновременно активных идентификаторов
ограничено 4096.

#### 3. Неограниченная приоритетная очередь TCP

При сетевом противодавлении служебные TCP-пакеты могли продолжать накапливаться
в связном списке без контроля количества элементов и суммарного размера.
Аутентифицированное, но злонамеренное или неисправное реле могло увеличивать
потребление памяти клиента.

**Возможные последствия:** исчерпание памяти и завершение процесса.

**Связь с RCE:** не обнаружена. Очередь росла за счёт корректных выделений
памяти; признаков записи за пределы выделенного буфера найдено не было.

Введены лимиты: 64 элемента и 128 КиБ на соединение, а также общий предел
2 МиБ. Если зашифрованный служебный пакет невозможно безопасно поставить в
очередь, закрывается только проблемное соединение. Такой вариант также
сохраняет однозначность криптографических nonce и счётчиков.

#### 4. Монополизация цикла обработки одним TCP-реле

Один обработчик мог читать данные от реле до полного опустошения сокета. При
непрерывном входящем потоке это позволяло одному соединению задерживать таймеры,
интерфейс и обслуживание остальных соединений.

**Возможные последствия:** высокая загрузка процессора, рост задержек и
частичная потеря работоспособности клиента.

**Связь с RCE:** отсутствует. Это атака на доступность и справедливое
распределение времени процессора.

Теперь за один проход обрабатывается не более 64 подтверждённых кадров или
128 КиБ данных. Остальные данные сохраняют порядок и продолжают обрабатываться
на следующей итерации.

#### 5. Дорогие криптографические вычисления до аутентификации UDP-пакета

Пакет с ранее неизвестным ключом мог вызвать вычисление общего ключа Curve25519
до полной проверки его подлинности. Отправляя множество пакетов с разными
ключами, атакующий мог создавать непропорционально высокую нагрузку на
процессор.

**Возможные последствия:** удалённый CPU DoS при включённом прямом
UDP-соединении.

**Связь с RCE:** отсутствует. Атакующий мог инициировать штатное, но дорогое
вычисление; нарушения границ памяти не было.

В форке введены глобальные и индивидуальные бюджеты вычислений, ограничение на
количество новых ключей за одну итерацию и конечная таблица источников.
Попадания в кэш не ограничиваются. Отдельное исправление учитывает реле, за
которым могут находиться многие легитимные пользователи, чтобы защита не
блокировала нормальный fan-in-трафик.

#### 6. Непропорциональное выделение памяти для очереди надёжной доставки

Окно приёма поддерживало до 32 768 позиций. Для маленького пакета могла
выделяться структура максимального размера. Добавленный контакт, отправляя
пакеты с разрывами в последовательности, мог удерживать около 43 МиБ памяти на
одно соединение.

**Возможные последствия:** контролируемое увеличение потребления памяти и отказ
в обслуживании со стороны уже принятого контакта.

**Связь с RCE:** не обнаружена. Размер выделения был избыточным, но последующая
запись соответствовала структуре; проблема заключалась в усилении расхода
памяти.

Теперь объём выделяемой памяти зависит от фактической длины пакета.
Дополнительно действует предел 8 МиБ на криптографическое соединение. При его
превышении закрывается только проблемное соединение — подтверждённый пакет
надёжной доставки не отбрасывается молча.

### Дополнительное исправление надёжности

Интервал повторной отправки запроса дружбы увеличивался экспоненциально и мог
становиться чрезмерно большим. В форке он ограничен 60 секундами, благодаря
чему восстановление связи после длительного офлайна остаётся предсказуемым.

Это исправление надёжности, а не RCE или самостоятельная уязвимость.

### Сводка по RCE

Из шести находок только ошибка сужения размера при выделении буфера относилась
к классу memory corruption и поэтому **теоретически могла стать основой для
выполнения произвольного кода**.

При этом важно разделять три разных утверждения:

- возможность повреждения памяти была подтверждена анализом исходного пути;
- потенциальная применимость такого класса ошибки для RCE известна в целом;
- конкретный удалённый RCE через сеть Tox **не был продемонстрирован и не должен
  заявляться как доказанный**.

Остальные пять проблем не давали обнаруженного примитива выполнения кода. Их
последствия ограничивались исчерпанием памяти, загрузкой процессора, задержкой
цикла событий или отключением соединения.

### Совместимость с Tox

Защитные изменения не создают новый протокол. В форке не менялись:

- форматы и идентификаторы сетевых пакетов;
- криптографические алгоритмы;
- представление ключей;
- правила nonce и криптографических счётчиков;
- формат сохранённых профилей;
- публичные максимумы сообщений, файлов и групп;
- публичные заголовки API.

Лимиты относятся к локальному потреблению памяти и процессорного времени. При
их исчерпании библиотека откладывает дальнейшую обработку, отклоняет запрос до
изменения состояния либо закрывает только проблемное соединение.

Для исправленных путей добавлены регрессионные тесты: граничные размеры,
переполнение очередей, справедливость между реле, лимиты групповых объявлений,
бюджеты криптографических вычислений, пропорциональное хранение пакетов,
повторная передача и освобождение памяти.

Форк не позиционируется как независимо сертифицированная криптографическая
реализация. Он не меняет криптографию Tox и не заменяет полноценный внешний
аудит. Его задача — устранить конкретные подтверждённые проблемы, обеспечить
воспроизводимость сетевого ядра Kaigen и установить конечные, проверяемые
пределы для ресурсов, которыми можно управлять через недоверенные входные
данные.

[**Website**](https://tox.chat) **|** [**Wiki**](https://wiki.tox.chat/) **|**
[**Blog**](https://blog.tox.chat/) **|**
[**FAQ**](https://wiki.tox.chat/doku.php?id=users:faq) **|**
[**Binaries/Downloads**](https://tox.chat/download.html) **|**
[**Clients**](https://wiki.tox.chat/doku.php?id=clients) **|**
[**Compiling**](/INSTALL.md)

## What is Tox

Tox is a peer to peer (serverless) instant messenger aimed at making security
and privacy easy to obtain for regular users. It uses
[libsodium](https://doc.libsodium.org/) (based on
[NaCl](https://nacl.cr.yp.to/)) for its encryption and authentication.

## IMPORTANT!

### ![Danger: Experimental](other/tox-warning.png)

This is an **experimental** cryptographic network library. It has not been
formally audited by an independent third party that specializes in cryptography
or cryptanalysis. **Use this library at your own risk.**

The underlying crypto library [libsodium](https://doc.libsodium.org/) provides
reliable encryption, but the security model has not yet been fully specified.
See [issue 210](https://github.com/TokTok/c-toxcore/issues/210) for a discussion
on developing a threat model. See other issues for known weaknesses (e.g.
[issue 426](https://github.com/TokTok/c-toxcore/issues/426) describes what can
happen if your secret key is stolen).

## Toxcore Development Roadmap

The roadmap and changelog are generated from GitHub issues. You may view them on
the website, where they are updated at least once every 24 hours:

- Changelog: https://toktok.ltd/changelog/c-toxcore
- Roadmap: https://toktok.ltd/roadmap/c-toxcore

## Installing toxcore

Detailed installation instructions can be found in [INSTALL.md](INSTALL.md).

The pinned `cmp` v20 source is included in `third_party/cmp`, so a normal clone
contains everything required from that dependency.

In a nutshell, if you have [libsodium](https://github.com/jedisct1/libsodium)
installed, run:

```sh
mkdir _build && cd _build
cmake ..
make
sudo make install
```

If you have [libvpx](https://github.com/webmproject/libvpx) and
[opus](https://github.com/xiph/opus) installed, the above will also build the
A/V library for multimedia chats.

## Using toxcore

The simplest "hello world" example could be an echo bot. Here we will walk
through the implementation of a simple bot.

### Creating the tox instance

All toxcore API functions work with error parameters. They are enums with one
`OK` value and several error codes that describe the different situations in
which the function might fail.

```c
TOX_ERR_NEW err_new;
Tox *tox = tox_new(NULL, &err_new);
if (err_new != TOX_ERR_NEW_OK) {
  fprintf(stderr, "tox_new failed with error code %d\n", err_new);
  exit(1);
}
```

Here, we simply exit the program, but in a real client you will probably want to
do some error handling and proper error reporting to the user. The `NULL`
argument given to the first parameter of `tox_new` is the `Tox_Options`. It
contains various write-once network settings and allows you to load a previously
serialised instance. See [toxcore/tox.h](tox.h) for details.

### Setting up callbacks

Toxcore works with callbacks that you can register to listen for certain events.
Examples of such events are "friend request received" or "friend sent a
message". Search the API for `tox_callback_*` to find all of them.

Here, we will set up callbacks for receiving friend requests and receiving
messages. We will always accept any friend request (because we're a bot), and
when we receive a message, we send it back to the sender.

```c
tox_callback_friend_request(tox, handle_friend_request);
tox_callback_friend_message(tox, handle_friend_message);
```

These two function calls set up the callbacks. Now we also need to implement
these "handle" functions.

### Handle friend requests

```c
static void handle_friend_request(
  Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
  void *user_data) {
  // Accept the friend request:
  TOX_ERR_FRIEND_ADD err_friend_add;
  tox_friend_add_norequest(tox, public_key, &err_friend_add);
  if (err_friend_add != TOX_ERR_FRIEND_ADD_OK) {
    fprintf(stderr, "unable to add friend: %d\n", err_friend_add);
  }
}
```

The `tox_friend_add_norequest` function adds the friend without sending them a
friend request. Since we already got a friend request, this is the right thing
to do. If you wanted to send a friend request yourself, you would use
`tox_friend_add`, which has an extra parameter for the message.

### Handle messages

Now, when the friend sends us a message, we want to respond to them by sending
them the same message back. This will be our "echo".

```c
static void handle_friend_message(
  Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
  const uint8_t *message, size_t length,
  void *user_data) {
  TOX_ERR_FRIEND_SEND_MESSAGE err_send;
  tox_friend_send_message(tox, friend_number, type, message, length,
    &err_send);
  if (err_send != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
    fprintf(stderr, "unable to send message back to friend %d: %d\n",
      friend_number, err_send);
  }
}
```

That's it for the setup. Now we want to actually run the bot.

### Main event loop

Toxcore works with a main event loop function `tox_iterate` that you need to
call at a certain frequency dictated by `tox_iteration_interval`. This is a
polling function that receives new network messages and processes them.

```c
while (true) {
  usleep(1000 * tox_iteration_interval(tox));
  tox_iterate(tox, NULL);
}
```

That's it! Now you have a working echo bot. The only problem is that since Tox
works with public keys, and you can't really guess your bot's public key, you
can't add it as a friend in your client. For this, we need to call another API
function: `tox_self_get_address(tox, address)`. This will fill the 38 byte
friend address into the `address` buffer. You can then display that binary
string as hex and input it into your client. Writing a `bin2hex` function is
left as exercise for the reader.

We glossed over a lot of details, such as the user data which we passed to
`tox_iterate` (passing `NULL`), bootstrapping into an actual network (this bot
will work in the LAN, but not on an internet server) and the fact that we now
have no clean way of stopping the bot (`while (true)`). If you want to write a
real bot, you will probably want to read up on all the API functions. Consult
the API documentation in [toxcore/tox.h](toxcore/tox.h) for more information.

### Other resources

- [Another echo bot](https://wiki.tox.chat/developers/client_examples/echo_bot)
- [minitox](https://github.com/hqwrong/minitox) (A minimal tox client)

## SAST Tools

This project uses various tools supporting Static Application Security Testing:

- [clang-tidy](https://clang.llvm.org/extra/clang-tidy/): A clang-based C++
  "linter" tool.
- [Coverity](https://scan.coverity.com/): A cloud-based static analyzer service
  for Java, C/C++, C#, JavaScript, Ruby, or Python that is free for open source
  projects.
- [cppcheck](https://cppcheck.sourceforge.io/): A static analyzer for C/C++
  code.
- [cpplint](https://github.com/cpplint/cpplint): Static code checker for C++
- [infer](https://github.com/facebook/infer): A static analyzer for Java, C,
  C++, and Objective-C.
- [PVS-Studio](https://pvs-studio.com/en/pvs-studio/?utm_source=website&utm_medium=github&utm_campaign=open_source):
  A static analyzer for C, C++, C#, and Java code.
- [tokstyle](https://github.com/TokTok/hs-tokstyle): A style checker for TokTok
  C projects.

## Acknowledgments

This project uses a number of excellent tools and services that are either free,
have a free tier, or are free for open source, which we would like to
acknowledge and give our thanks to:

- [GitHub](https://github.com) - source code hosting, issue tracking, code
  collaboration and release hosting
- [Reviewable](https://www.reviewable.io) - enhanced code review experience
- [Docker](https://www.docker.com) - reproducible test and build environment and
  container hosting
- [Azure Pipelines](https://azure.microsoft.com/en-us/products/devops/pipelines),
  [CircleCI](https://circleci.com),
  [Cirrus CI](https://cirrus-ci.org),
  [GitHub Actions](https://github.com/features/actions) -
  continuous integration (CI) making sure our code builds and passes the tests
  across different platforms and configurations
- [clang-tidy](https://clang.llvm.org/extra/clang-tidy),
  [clang-analyzer](https://clang-analyzer.llvm.org),
  [CodeQL](https://codeql.github.com),
  [Coverity Scan](https://scan.coverity.com),
  [cppcheck](https://cppcheck.sourceforge.io),
  [cpplint](https://github.com/cpplint/cpplint),
  [Goblint](https://goblint.in.tum.de),
  [Infer](https://fbinfer.com),
  [PVS-Studio](https://pvs-studio.com),
  [Sparse](https://sparse.docs.kernel.org) -
  linters and static code analysis tools making sure out code remains as
  bug-free as possible
- [Clang ASan (AddressSanitizer)](https://clang.llvm.org/docs/AddressSanitizer.html),
  [Clang MSan (MemorySanitizer)](https://clang.llvm.org/docs/MemorySanitizer.html),
  [Clang TSan (ThreadSanitizer)](https://clang.llvm.org/docs/ThreadSanitizer.html),
  [Clang UBSan (UndefinedBehaviorSanitizer)](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) -
  dynamic code analysis tools making sure out code remains as bug-free as
  possible
- [AFLplusplus](https://aflplus.plus),
  [ClusterFuzzLite](https://google.github.io/clusterfuzzlite) -
  continuous fuzz testing for detecting crashes and vulnerabilities
- [Codacy](https://www.codacy.com),
  [CodeFactor](https://www.codefactor.io),
  [Sonar](https://www.sonarsource.com) -
  code quality, security and maintainability review and metrics
- [CompCert](https://compcert.org),
  [slimcc](https://github.com/fuhsnn/slimcc),
  [tcc](https://bellard.org/tcc) -
  alternative and formally verified compilers used for portability and
  correctness testing
- [mingw-w64](https://www.mingw-w64.org),
  [Wine](https://www.winehq.org) -
  Windows cross-compilation and testing
- [astyle](https://astyle.sourceforge.net),
  [clang-format](https://clang.llvm.org/docs/ClangFormat.html),
  [Restyled](https://restyled.io) -
  automated code formatting
- [Codecov](https://about.codecov.io) - code coverage reporting
- [Dependabot](https://github.com/dependabot) - automated dependency updates
- [doxygen](https://www.doxygen.nl/),
  [Netlify](https://www.netlify.com) -
  documentation generation and hosting

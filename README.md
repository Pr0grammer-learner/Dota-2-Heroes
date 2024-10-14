# Dota 2 Heroes Web Application

## Описание

Этот проект представляет собой веб-приложение, созданное с использованием Express.js и базы данных MySQL. Сайт посвящён игре Dota 2 и предоставляет информацию о героях, их способностях, а также даёт возможность пользователям регистрироваться, авторизовываться, оставлять комментарии и взаимодействовать с контентом.

## Функциональные возможности

- Регистрация и авторизация пользователей с использованием bcrypt для хеширования паролей.
- Добавление и отображение комментариев на страницах героев.
- Панель администратора для управления информацией о героях.
- Страница с обратной связью.
- Загрузка статических файлов (изображений и стилей) через папку `public`.
- Валидация данных с помощью модуля `validator`.
- Обработка загружаемых файлов с помощью `multer`.
- Поддержка сессий для хранения данных о пользователе.

## Стек технологий

- **Node.js**
- **Express.js**
- **MySQL**
- **bcrypt** для хеширования паролей
- **multer** для загрузки файлов
- **EJS** для рендеринга HTML-шаблонов
- **body-parser** для обработки POST-запросов
- **express-session** для работы с сессиями
- **method-override** для обработки PUT и DELETE-запросов

## Установка

1. Склонируйте репозиторий на свой компьютер:

```bash
   git clone https://github.com/Pr0grammer-learner/Dota-2-Heroes.git
```

2. Перейдите в директорию проекта:

```bash
   cd Dota-2-Heroes
```

3. Установите все необходимые зависимости:

```bash
  npm i
```

4. Создайте файл .env и укажите необходимые параметры:

```bash
  DB_HOST=localhost
  DB_USER=root
  DB_NAME=dota2_heroes
  DB_PASSWORD=password
  PORT=3000
```

5. Запустите сервер:

```bash
   npm start
```

6. Откройте браузер и перейдите по адресу:

```bash
   http://localhost:3000
```

## Структура проекта
```plaintext
├── public/         # Папка со статическими файлами (CSS, изображения)
├── views/          # Шаблоны EJS
├── routes/         # Маршруты для страниц сайта
├── controllers/    # Логика обработки запросов
├── models/         # Взаимодействие с базой данных
└── app.js          # Главный файл приложения
```

## Маршруты
- / – главная страница со списком героев.
- /auth – страница регистрации и авторизации.
- /admin – панель администратора.
- /feedback – страница обратной связи.
- /hero/:name – страница с информацией о герое и его способностях.
- /logout – выход из аккаунта.
  
## База данных
Пример структуры базы данных:
+ users – таблица пользователей (username, email, password, role).
+ heroes – таблица героев.
+ abilities – таблица способностей героев.
+ comments – таблица комментариев.
```plaintext
users
-----------------------
| id  | INT (PK, AI)   |
| username | VARCHAR   |
| email    | VARCHAR   |
| password | VARCHAR   |
| role     | ENUM      |
-----------------------

heroes
-----------------------
| id       | INT (PK, AI)   |
| name     | VARCHAR         |
| role     | VARCHAR         |
| primary_attribute | ENUM   |
| bio      | TEXT            |
| image_url | VARCHAR        |
-----------------------

abilities
-------------------------
| id          | INT (PK, AI) |
| hero_id     | INT (FK)     |
| name        | VARCHAR      |
| description | TEXT         |
| cooldown    | INT          |
| mana_cost   | INT          |
-------------------------

comments
-------------------------
| id        | INT (PK, AI)   |
| user_id   | INT (FK)       |
| hero_id   | INT (FK)       |
| content   | TEXT           |
| created_at| TIMESTAMP      |
-------------------------
```

## Авторизация и роли
* Пользователи могут регистрироваться и авторизовываться для доступа к расширенным функциям сайта.
* Роли пользователей:
   * Обычный пользователь – может просматривать героев, оставлять комментарии.
   * Администратор – имеет доступ к панели администрирования для управления контентом сайта.

## Окружение
* Node.js: минимальная версия 14.
* MySQL: локальная или удалённая база данных для хранения данных сайта.

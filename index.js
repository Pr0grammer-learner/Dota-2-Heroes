require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser')
const methodOverride = require('method-override');
const validator = require('validator');
const mysql = require("mysql2");
const multer = require('multer');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000; // Порт, на котором будет работать сервер
const saltRounds = 10; // Количество раундов для генерации соли

// Создаем подключение к базе данных
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD
});

  
// Доверять первому прокси-серверу
app.set('trust proxy', 1);

// Подключаем method-override
app.use(methodOverride('_method'));


// Настройка сеанса
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
  }));

// Подключаемся к базе данных
connection.connect((err) => {
    if (err) {
      console.error('Ошибка подключения к базе данных: ' + err.stack);
      return;
    }
    console.log('Успешное подключение к базе данных');
  });

// create application/x-www-form-urlencoded parser
let urlencodedParser = bodyParser.urlencoded({ extended: false })

// Устанавливаем шаблонизатор EJS
app.set('view engine', 'ejs');

// Подключаем статические файлы из папки public
app.use(express.static(path.join(__dirname, 'public')));

// Middleware для передачи данных сессии в res.locals
app.use((req, res, next) => {
    console.log('Session:', req.session); // Логирование сессии
    res.locals.session = req.session;
    next();
  });

// Маршрут для главной страницы
app.get('/', (req, res) => {
    const query = 'SELECT * FROM heroes';
    connection.query(query, (err, results) => {
        if (err) {
            console.error('Ошибка при выполнении запроса: ' + err.stack);
            return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса', link: '/' });
        }

        res.status(200).render('index', { heroes: results, session: req.session }); // Рендерим шаблон index.ejs
    });
});

function checkRole(role) {
    return function(req, res, next) {
        if (!req.session.user) {
            res.render('error', { errorMessage: 'К сожалению, вы не авторизовались!', link: '/auth' }); // Перенаправляем пользователя на страницу ошибки
        } else if (req.session.user.role === role) {
            next(); // Продолжаем выполнение следующего middleware или маршрута
        } else {
            res.render('error', { errorMessage: 'К сожалению, у вас не достаточно прав!', link: '/' }); // Перенаправляем пользователя на страницу ошибки
        }
    }
}

// Маршрут для страницы обратной связи
app.get('/feedback', (req, res) => {
    res.status(200).render('feedback'); // Рендерим шаблон feedback.ejs с кодом состояния 200
});

// Маршрут для страницы регистрации
app.get('/auth', (req, res) => {
    res.status(200).render('auth'); // Рендерим шаблон auth.ejs с кодом состояния 200
});

// Маршрут для регистрации
app.post('/registration', urlencodedParser, (req, res) => {
    const { User_email, User_password, User_password_confirm, User_name } = req.body;

    if (!validator.isEmail(User_email)) {
        return res.status(400).render('error', { errorMessage: 'Введите валидный Email!', link: '/auth' });
    }
    if (User_password !== User_password_confirm) {
        return res.status(400).render('error', { errorMessage: 'Пароли не совпадают!', link: '/auth' });
    }

    // Проверяем, не используется ли уже этот email
    connection.query('SELECT * FROM users WHERE email = ?', [User_email], (err, emailResults) => {
        if (err) {
            console.error('Ошибка при выполнении запроса: ' + err.stack);
            return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса', link: '/auth' });
        }

        if (emailResults.length > 0) {
            return res.status(409).render('error', { errorMessage: 'Пользователь с таким email уже существует!', link: '/auth' });
        }

        // Проверяем, не используется ли уже этот username
        connection.query('SELECT * FROM users WHERE username = ?', [User_name], (err, usernameResults) => {
            if (err) {
                console.error('Ошибка при выполнении запроса: ' + err.stack);
                return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса', link: '/auth' });
            }

            if (usernameResults.length > 0) {
                return res.status(409).render('error', { errorMessage: 'Пользователь с таким username уже существует!', link: '/auth' });
            }

            // Хэшируем пароль перед добавлением в базу данных
            bcrypt.hash(User_password, saltRounds, (err, hashedPassword) => {
                if (err) {
                    console.error('Ошибка при хэшировании пароля: ' + err.stack);
                    return res.status(500).render('error', { errorMessage: 'Ошибка при хэшировании пароля', link: '/auth' });
                }

                // Если проверки пройдены, добавляем пользователя в базу данных
                connection.query('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', [User_name, User_email, hashedPassword, 'user'], (err, results) => {
                    if (err) {
                        console.error('Ошибка при добавлении пользователя: ' + err.stack);
                        return res.status(500).render('error', { errorMessage: 'Ошибка при добавлении пользователя', link: '/auth' });
                    }
                    console.log('Пользователь успешно добавлен в базу данных');
                    res.status(201).render('error', { errorMessage: 'Пользователь успешно зарегистрирован!', link: '/' });
                });
            });
        });
    });
});

// Маршрут для обработки формы обратной связи
app.post('/feedback_answer', urlencodedParser, (req, res) => {
    const { Username, Useremail, Theme, Message } = req.body;

    // Проверка на заполненность всех полей
    if (!Username || !Useremail || !Theme || !Message) {
        return res.status(400).send('Все поля должны быть заполнены.');
    }

    const sql = 'INSERT INTO feedback (user_name, user_email, theme, message) VALUES (?, ?, ?, ?)';
    connection.query(sql, [Username, Useremail, Theme, Message], (err, result) => {
        if (err) {
            console.error('Ошибка при сохранении отзыва в базе данных:', err);
            return res.status(500).send('Ошибка при сохранении отзыва в базе данных.');
        }
        res.status(201).render('error', { errorMessage: 'Спасибо за ваш отзыв!', link: '/' });
    });
});

// Маршрут для авторизации
app.post('/login', urlencodedParser, (req, res) => {
    const { User_name, User_password } = req.body;

    // Запрос для проверки наличия пользователя с указанным email или username
    connection.query('SELECT * FROM users WHERE email = ? OR username = ?', [User_name, User_name], (err, results) => {
        if (err) {
            console.error('Ошибка при выполнении запроса: ' + err.stack);
            return res.status(500).send('Ошибка при выполнении запроса');
        }

        // Проверяем, найден ли пользователь
        if (results.length === 0) {
            return res.status(404).render('error', { errorMessage: 'Пользователь с указанным email или username не найден', link: '/auth' });
        }

        const user = results[0];

        // Проверяем правильность введенного пароля
        bcrypt.compare(User_password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Ошибка при проверке пароля: ' + err.stack);
                return res.status(500).send('Ошибка при проверке пароля');
            }

            if (!isMatch) {
                return res.status(401).render('error', { errorMessage: 'Неправильный пароль', link: '/auth' });
            }

            // Если все проверки пройдены успешно, сохраняем информацию о пользователе в сессии
            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role
            };

            // Перенаправление пользователя на главную страницу
            res.status(200).redirect('/');
        });
    });
});

// Маршрут для страницы админки
app.get('/admin', checkRole('admin'), (req, res) => {
    if (req.session.user) {
        // Выполняем запрос для получения списка героев
        connection.query('SELECT * FROM heroes', (err, heroes) => {
            if (err) {
                console.error('Ошибка при выполнении запроса: ' + err.stack);
                return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса к базе данных', link: '/' });
            }

            // Рендерим страницу админки с переданным списком героев
            res.status(200).render('admin', { heroes });
        });
    } else {
        res.status(401).render('error', { errorMessage: 'Вы не авторизованы!', link: '/auth' });
    }
});


app.get('/get_feedback', checkRole('admin'), (req, res) => {
    connection.query('SELECT * FROM feedback', (err, feedback) => {
        if (err) {
            console.error('Ошибка при выполнении запроса: ' + err.stack);
            return res.status(500).json({ errorMessage: 'Ошибка при выполнении запроса к базе данных' });
        }
        console.log(feedback);
        res.status(200).json({ feedback });
    });
});

// Маршрут для выхода из системы
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Ошибка при завершении сессии: ' + err.stack);
            return res.status(500).send('Ошибка при завершении сессии');
        }
        res.status(200).redirect('/'); // Перенаправляем на главную страницу после выхода
    });
});

app.get('/hero/:name', (req, res) => {
    const heroName = req.params.name;
    const heroQuery = 'SELECT * FROM heroes WHERE name = ?';
    const abilitiesQuery = 'SELECT * FROM abilities WHERE hero_id = ?';
    const commentsQuery = 'SELECT * FROM comments WHERE hero_id = ?';

    connection.query(heroQuery, [heroName], (err, heroResults) => {
        if (err) {
            console.error('Ошибка при выполнении запроса для героя: ' + err.stack);
            return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса', link: '/' });
        }

        if (heroResults.length === 0) {
            return res.status(404).render('error', { errorMessage: 'Герой не найден', link: '/' });
        }

        const hero = heroResults[0];

        connection.query(abilitiesQuery, [hero.hero_id], (err, abilitiesResults) => {
            if (err) {
                console.error('Ошибка при выполнении запроса для способностей: ' + err.stack);
                return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса', link: '/' });
            }

            connection.query(commentsQuery, [hero.hero_id], (err, commentsResults) => {
                if (err) {
                    console.error('Ошибка при выполнении запроса для комментариев: ' + err.stack);
                    return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса', link: '/' });
                }
                console.log(hero);
                res.status(200).render('hero', { hero: hero, abilities: abilitiesResults, comments: commentsResults });
            });
        });
    });
});

// Обработчик маршрута для добавления комментариев
app.post('/add_comment', urlencodedParser, (req, res) => {
    // Получение данных из тела запроса
    const { comment, hero_id } = req.body;
    console.log(hero_id);

    // Проверка, авторизован ли пользователь
    if (!req.session.user) {
        return res.status(401).render('error', { errorMessage: 'Пользователь не авторизован', link: `/auth` });
    }

    // Проверка на пустой комментарий
    if (!comment || comment.trim() === '') {
        return res.status(400).render('error', {errorMessage: 'Комментарий не может быть пустым', link: `/` });
    }

    // Вставка комментария в базу данных
    const insertCommentQuery = 'INSERT INTO comments (username, text, hero_id) VALUES (?, ?, ?)';
    connection.query(insertCommentQuery, [req.session.user.username, comment, hero_id], (err, result) => {
        if (err) {
            console.error('Ошибка при добавлении комментария: ' + err.stack);
            return res.status(500).render('error', { errorMessage: 'Ошибка при добавлении комментария', link: `/` });
        }
        console.log('Комментарий успешно добавлен');
        res.status(200).render('error', { errorMessage: 'Комментарий успешно добавлен', link: `/` });
    });
});

// Конфигурация хранения файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images');
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

app.post('/Add_card', upload.fields([{ name: 'image_url' }, { name: 'background_image_url' }]), checkRole('admin'), (req, res) => {
    const {
        name, primary_attribute, attack_type, complexity,
        short_description, full_story_url, background_color,
        text_color, highlight_color, secondary_color
    } = req.body;

    if (!name || !primary_attribute || !attack_type || !complexity) {
        return res.status(400).render('error', { errorMessage: 'Все обязательные поля должны быть заполнены', link: '/admin' });
    }

    const image_url = '/images/' + req.files['image_url'][0].filename;
    const background_image_url = '/images/' + req.files['background_image_url'][0].filename;

    // Проверка наличия героя в базе данных перед добавлением
    const checkQuery = 'SELECT * FROM heroes WHERE name = ?';
    connection.query(checkQuery, [name], (err, results) => {
        if (err) {
            console.error('Ошибка при выполнении запроса: ' + err.stack);
            return res.status(500).render('error', { errorMessage: 'Ошибка при проверке наличия героя', link: '/admin' });
        }

        if (results.length > 0) {
            return res.status(409).render('error', { errorMessage: 'Данный герой уже добавлен!', link: '/admin' });
        }

        // Если героя нет в базе данных, добавляем новую карточку
        const query = `INSERT INTO heroes 
            (name, primary_attribute, image_url, attack_type, complexity, short_description, full_story_url, background_color, text_color, highlight_color, secondary_color, background_image_url) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        connection.query(query, [
            name, primary_attribute, image_url, attack_type, complexity,
            short_description, full_story_url, background_color,
            text_color, highlight_color, secondary_color, background_image_url
        ], (err, results) => {
            if (err) {
                console.error('Ошибка при добавлении героя: ' + err.stack);
                return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса', link: '/admin' });
            }
            // Перенаправление пользователя на страницу с уведомлением об успешном добавлении
            res.status(200).render('error', { errorMessage: 'Карточка успешно добавлена', link: '/admin' });
        });
    });
});

app.delete('/Delete_card', urlencodedParser, checkRole('admin'), (req, res) => {
    const heroId = req.body.hero_id;

    // Удаляем карточку героя из базы данных
    connection.query('DELETE FROM heroes WHERE hero_id = ?', [heroId], (err, result) => {
        if (err) {
            console.error('Ошибка при удалении карточки героя: ' + err.stack);
            return res.status(500).render('error', { errorMessage: 'Ошибка при удалении карточки героя', link: '/admin' });
        }
        // Перенаправляем пользователя на страницу админки после успешного удаления
        res.status(200).redirect('/admin');
    });
});

app.get('/get_abilities/:heroId', (req, res) => {
    const heroId = req.params.heroId;
    
    // Запрос к базе данных для получения списка способностей по выбранному герою
    connection.query('SELECT * FROM abilities WHERE hero_id = ?', [heroId], (err, abilities) => {
        if (err) {
            console.error('Ошибка при выполнении запроса для списка способностей: ' + err.stack);
            return res.status(500).render('error', { errorMessage: 'Ошибка при выполнении запроса для списка способностей', link: '/admin' });
        }
        // Отправляем список способностей в формате JSON
        res.json({ abilities: abilities });
    });
});

app.delete('/delete_ability/:abilityId', checkRole('admin'),  urlencodedParser, (req, res) => {
    const abilityId = req.params.abilityId;
    console.log(abilityId);
    
    // Удаляем способность из базы данных
    connection.query('DELETE FROM abilities WHERE ability_id = ?', [abilityId], (err, result) => {
        if (err) {
            console.error('Ошибка при удалении способности: ' + err.stack);
            return res.status(500).render('error', { errorMessage: 'Ошибка при удалении способности', link: '/admin' })
        }
        // Отправляем ответ об успешном удалении
        res.sendStatus(200);
    });
});

// Конфигурация хранения файлов для способностей
const abilityStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, 'public/images/abilities');
        } else if (file.mimetype.startsWith('video/')) {
            cb(null, 'public/videos/abilities');
        } else {
            cb(new Error('Invalid file type'), null);
        }
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        const fileName = file.fieldname + '-' + uniqueSuffix + ext;
        req.uploadedFileName = fileName; // Добавляем в объект запроса имя загруженного файла
        cb(null, fileName);
    }
});

const abilityUpload = multer({ storage: abilityStorage });

app.post('/Add_ability', checkRole('admin'), abilityUpload.fields([
    { name: 'image_url', maxCount: 1 },
    { name: 'video_url', maxCount: 1 }
]), (req, res) => {
    const { hero_id, name, description, specification } = req.body;
    const image_url = req.files['image_url'] ? '/images/abilities/' + req.files['image_url'][0].filename : null;
    const video_url = req.files['video_url'] ? '/videos/abilities/' + req.files['video_url'][0].filename : null;

    if (!hero_id || !name || !description || !specification || !image_url) {
        return res.render('error', { errorMessage: 'Обязательные поля не заполнены', link: '/admin' });
    }

    // Проверка, является ли specification валидным JSON
    if (!validator.isJSON(specification)) {
        return res.render('error', { errorMessage: 'Specification должно быть валидным JSON', link: '/admin' });
    }

    const query = `INSERT INTO abilities (hero_id, name, image_url, video_url, description, specification) 
                   VALUES (?, ?, ?, ?, ?, ?)`;

    connection.query(query, [hero_id, name, image_url, video_url, description, specification], (err, results) => {
        if (err) {
            console.error('Ошибка при добавлении способности: ' + err.stack);
            return res.render('error', { errorMessage: 'Ошибка при добавлении способности', link: '/admin' });
        }
        res.render('error', { errorMessage: 'Способность успешно добавлена', link: '/admin' });
    });
});

app.get('/edit_hero/:heroId', checkRole('admin'), urlencodedParser, (req, res) => {
    const heroId = req.params.heroId;
    
    connection.query(
        'SELECT h.hero_id, h.name, h.primary_attribute, h.image_url, h.attack_type, h.complexity, h.short_description, h.full_story_url, h.background_color, h.text_color, h.highlight_color, h.secondary_color, h.background_image_url, a.ability_id, a.name AS ability_name, a.image_url AS ability_image_url, a.video_url, a.description, a.specification FROM heroes h LEFT JOIN abilities a ON h.hero_id = a.hero_id WHERE h.hero_id = ?',
        [heroId],
        (err, results) => {
            if (err) {
                console.error('Ошибка при загрузке информации о герое: ' + err.stack);
                return res.status(500).render('error', { errorMessage: 'Ошибка при загрузке информации о герое:', link: '/admin' });
            }

            if (results.length === 0) {
                return res.status(404).render('error', { errorMessage: 'Герой не найден', link: '/admin' });
            }

            // Получение информации по герою
            const hero = {
                hero_id: results[0].hero_id,
                name: results[0].name,
                primary_attribute: results[0].primary_attribute,
                image_url: results[0].image_url,
                attack_type: results[0].attack_type,
                complexity: results[0].complexity,
                short_description: results[0].short_description,
                full_story_url: results[0].full_story_url,
                background_color: results[0].background_color,
                text_color: results[0].text_color,
                highlight_color: results[0].highlight_color,
                secondary_color: results[0].secondary_color,
                background_image_url: results[0].background_image_url
            };

            // Получение информации по способностям 
            const abilities = results
                .filter(row => row.ability_id !== null)
                .map(row => ({
                    ability_id: row.ability_id,
                    name: row.ability_name,
                    image_url: row.ability_image_url,
                    video_url: row.video_url,
                    description: row.description,
                    specification: row.specification
                }));

            res.render('edit_hero', { hero: hero, abilities: abilities });
        }
    );
});


const heroStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images');
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const heroUpload = multer({ storage: heroStorage });

app.put('/hero_edit/:heroId', checkRole('admin'), heroUpload.fields([
    { name: 'image_url', maxCount: 1 },
    { name: 'background_image_url', maxCount: 1 }
]), (req, res) => {
    const heroId = req.params.heroId;
    const heroData = req.body;
    console.log(heroData);

    let image_url = req.body.existing_image_url;
    let background_image_url = req.body.existing_background_image_url;

    if (req.files['image_url']) {
        image_url = '/images/' + req.files['image_url'][0].filename;
    }

    if (req.files['background_image_url']) {
        background_image_url = '/images/' + req.files['background_image_url'][0].filename;
    }

    // Обновление данных героя
    const updateHeroQuery = `
        UPDATE heroes SET 
        name = ?, 
        primary_attribute = ?, 
        image_url = ?, 
        attack_type = ?, 
        complexity = ?, 
        short_description = ?, 
        full_story_url = ?, 
        background_color = ?, 
        text_color = ?, 
        highlight_color = ?, 
        secondary_color = ?, 
        background_image_url = ?
        WHERE hero_id = ?`;
    
    const heroValues = [
        heroData.name, 
        heroData.primary_attribute, 
        image_url,
        heroData.attack_type, 
        heroData.complexity, 
        heroData.short_description, 
        heroData.full_story_url, 
        heroData.background_color, 
        heroData.text_color, 
        heroData.highlight_color, 
        heroData.secondary_color, 
        background_image_url,
        heroId
    ];

    connection.query(updateHeroQuery, heroValues, (err, result) => {
        if (err) {
            console.error('Ошибка при обновлении героя: ' + err.stack);
            return res.render('error', { errorMessage: 'Ошибка при обновлении героя', link: '/admin' });
        }
        console.log('Герой успешно обновлен');
        res.render('error', { errorMessage: 'Герой успешно обновлен', link: `/edit_hero/${heroId}` });
    });
});

app.put('/edit_ability/:abilityId', checkRole('admin'), abilityUpload.fields([
    { name: 'image_url', maxCount: 1 },
    { name: 'video_url', maxCount: 1 }
]), (req, res) => {
    const abilityId = req.params.abilityId;
    const { hero_id, name, description, specification } = req.body;

    let image_url = req.body.existing_image_url;
    let video_url = req.body.existing_video_url;

    if (req.files['image_url']) {
        image_url = '/images/abilities/' + req.files['image_url'][0].filename;
    }

    if (req.files['video_url']) {
        video_url = '/videos/abilities/' + req.files['video_url'][0].filename;
    }

    // Проверка, является ли specification валидным JSON
    let parsedSpecification;
    try {
        parsedSpecification = JSON.parse(specification);
    } catch (err) {
        return res.render('error', { errorMessage: 'Неверный формат JSON для specification', link: '/admin' });
    }

    // Обновление данных способности
    const updateAbilityQuery = `
        UPDATE abilities SET 
        hero_id = ?, 
        name = ?, 
        image_url = ?, 
        video_url = ?, 
        description = ?, 
        specification = ?
        WHERE ability_id = ?`;

    const abilityValues = [
        hero_id,
        name,
        image_url,
        video_url,
        description,
        specification,
        abilityId
    ];

    connection.query(updateAbilityQuery, abilityValues, (err, result) => {
        if (err) {
            console.error('Ошибка при обновлении способности: ' + err.stack);
            return res.render('error', { errorMessage: 'Ошибка при обновлении способности', link: `/admin` });
        }
        console.log('Способность успешно обновлена');
        res.render('error', { errorMessage: 'Способность успешно обновлена', link: `/admin` });
    });
});


// Маршрут для страницы 404
app.use((req, res) => {
    res.status(404).render('404'); // Рендерим страницу 404
});

// Запускаем сервер
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

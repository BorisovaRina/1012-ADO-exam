using System;
using System.Data;
using System.Data.SqlClient;
using System.Text;

namespace ConsoleApp37
{
    internal class Program
    {
        // Подключение к LocalDB (автоматически создаётся при первом запуске)
        private static readonly string connectionString =
            @"Data Source=(localdb)\MSSQLLocalDB;Initial Catalog=SecurityDemoDB;Integrated Security=True;";

        private static readonly string dbName = "SecurityDemoDB";
        private static readonly string tableName = "Users";

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║          SQL Injection в ADO.NET                             ║");
            Console.WriteLine("║                  Задания 2.1 и 2.2                           ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════╝\n");
            Console.ResetColor();

            // Шаг 1: Создаём базу данных и таблицу
            InitializeDatabase();

            // Шаг 2: Добавляем тестовых пользователей
            InsertTestData();

            // ══════════════════════════════════════════════════════════════
            // Задание 2.1
            // ══════════════════════════════════════════════════════════════
            Console.WriteLine("".PadRight(80, '='));
            Console.WriteLine("ЗАДАНИЕ 2.1: Поиск пользователя по email — безопасный способ (параметры)");
            Console.WriteLine("".PadRight(80, '='));
            SafeSearchByEmail("admin@example.com");
            SafeSearchByEmail("user1@test.com");
            SafeSearchByEmail("несуществующий@email.ru");

            // Демонстрация опасности конкатенации
            Console.WriteLine("\n\n");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ОСТОРОЖНО! ДЕМОНСТРАЦИЯ ОПАСНОСТИ КОНКАТЕНАЦИИ СТРОК");
            Console.ResetColor();
            DemonstrateStringConcatenationDanger();

            // ══════════════════════════════════════════════════════════════
            // Задание 2.2
            // ══════════════════════════════════════════════════════════════
            Console.WriteLine("\n\n" + "".PadRight(80, '='));
            Console.WriteLine("ЗАДАНИЕ 2.2: Полная демонстрация SQL-инъекции и защита от неё");
            Console.WriteLine("".PadRight(80, '='));
            FullSqlInjectionDemo();

            // Завершение
            Console.WriteLine("\n\n");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Все задания успешно выполнены!");
            Console.WriteLine("Главное правило: НИКОГДА не конкатенируйте пользовательский ввод в SQL-запросы!");
            Console.WriteLine("Используйте ТОЛЬКО параметризованные запросы!");
            Console.ResetColor();

            Console.WriteLine("\nНажмите любую клавишу для выхода...");
            Console.ReadKey();
        }

        // Создание базы и таблицы (один раз)
        private static void InitializeDatabase()
        {
            // Сначала создаём базу, если её нет
            string masterConnection = @"Data Source=(localdb)\MSSQLLocalDB;Initial Catalog=master;Integrated Security=True;";

            using (var conn = new SqlConnection(masterConnection))
            {
                conn.Open();
                string checkDb = $"SELECT COUNT(*) FROM sys.databases WHERE name = '{dbName}'";
                using (var cmd = new SqlCommand(checkDb, conn))
                {
                    int exists = (int)cmd.ExecuteScalar();
                    if (exists == 0)
                    {
                        Console.WriteLine($"Создаём базу данных {dbName}...");
                        string createDb = $"CREATE DATABASE {dbName}";
                        using (var createCmd = new SqlCommand(createDb, conn))
                        {
                            createCmd.ExecuteNonQuery();
                        }
                        Console.WriteLine("База данных создана.");
                    }
                    else
                    {
                        Console.WriteLine($"База данных {dbName} уже существует.");
                    }
                }
            }

            // Теперь подключаемся к нашей БД и создаём таблицу
            using (var conn = new SqlConnection(connectionString))
            {
                conn.Open();

                // Удаляем таблицу, если она уже есть (для чистоты эксперимента)
                string dropTable = $"IF OBJECT_ID('{tableName}', 'U') IS NOT NULL DROP TABLE {tableName};";
                using (var cmd = new SqlCommand(dropTable, conn))
                {
                    cmd.ExecuteNonQuery();
                }

                // Создаём таблицу Users
                string createTable = $@"
                    CREATE TABLE {tableName} (
                        Id INT IDENTITY(1,1) PRIMARY KEY,
                        Email NVARCHAR(255) NOT NULL UNIQUE,
                        PasswordHash NVARCHAR(255) NOT NULL,
                        FullName NVARCHAR(255),
                        Role NVARCHAR(50) NOT NULL DEFAULT 'User',
                        CreatedAt DATETIME DEFAULT GETDATE()
                    );";

                using (var cmd = new SqlCommand(createTable, conn))
                {
                    cmd.ExecuteNonQuery();
                    Console.WriteLine($"Таблица {tableName} создана.");
                }
            }
        }

        // Вставка тестовых данных
        private static void InsertTestData()
        {
            Console.WriteLine("Добавляем тестовых пользователей...");
            using (var conn = new SqlConnection(connectionString))
            {
                conn.Open();

                var users = new[]
                {
                    ("admin@example.com", "AdminPass123", "Администратор Системы", "Administrator"),
                    ("user1@test.com", "User12345", "Иванов Иван Иванович", "User"),
                    ("manager@company.ru", "Manager777", "Петров Пётр Петрович", "Manager"),
                    ("guest@mail.ru", "guest", "Гость", "Guest")
                };

                string sql = $"INSERT INTO {tableName} (Email, PasswordHash, FullName, Role) VALUES (@Email, @Pass, @Name, @Role)";

                foreach (var user in users)
                {
                    using (var cmd = new SqlCommand(sql, conn))
                    {
                        cmd.Parameters.AddWithValue("@Email", user.Item1);
                        cmd.Parameters.AddWithValue("@Pass", user.Item2);
                        cmd.Parameters.AddWithValue("@Name", user.Item3);
                        cmd.Parameters.AddWithValue("@Role", user.Item4);
                        cmd.ExecuteNonQuery();
                    }
                }
                Console.WriteLine($"Добавлено {users.Length} пользователей.\n");
            }
        }

        // Задание 2.1 — Безопасный поиск по email (параметризованный запрос)
        private static void SafeSearchByEmail(string email)
        {
            Console.WriteLine($"\nПоиск пользователя по email: \"{email}\"");

            using (var conn = new SqlConnection(connectionString))
            {
                conn.Open();

                // ПРАВИЛЬНЫЙ СПОСОБ — параметризованный запрос
                string sql = $"SELECT Id, Email, FullName, Role FROM {tableName} WHERE Email = @Email";

                using (var cmd = new SqlCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@Email", email);

                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"    УСПЕШНО НАЙДЕН:");
                            Console.WriteLine($"    Id: {reader["Id"]}");
                            Console.WriteLine($"    Email: {reader["Email"]}");
                            Console.WriteLine($"    Имя: {reader["FullName"]}");
                            Console.WriteLine($"    Роль: {reader["Role"]}");
                            Console.ResetColor();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("    Пользователь с таким email не найден.");
                            Console.ResetColor();
                        }
                    }
                }
            }
        }

        // Демонстрация опасности конкатенации строк
        private static void DemonstrateStringConcatenationDanger()
        {
            string maliciousInput = "xyz@example.com' OR '1'='1";

            Console.WriteLine($"\nВведён вредоносный email: \"{maliciousInput}\"");

            using (var conn = new SqlConnection(connectionString))
            {
                conn.Open();

                // ОПАСНЫЙ способ — конкатенация строки
                string dangerousSql = $"SELECT Id, Email, FullName, Role FROM {tableName} WHERE Email = '{maliciousInput}'";

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nВыполняется НЕБЕЗОПАСНЫЙ запрос:");
                Console.WriteLine(dangerousSql);
                Console.WriteLine("\nРезультат (ВЗЛОМ!):");
                Console.ResetColor();

                using (var cmd = new SqlCommand(dangerousSql, conn))
                {
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Console.WriteLine($"    ВЗЛОМ! Показан: {reader["Email"]} — {reader["FullName"]} (Роль: {reader["Role"]})");
                        }
                    }
                }
            }

            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("\nВНИМАНИЕ: Атакующий получил доступ ко ВСЕМ пользователям без ввода правильного логина!");
            Console.WriteLine("Это классическая SQL-инъекция первого порядка.");
            Console.ResetColor();
        }

        // Задание 2.2 — Полная демонстрация атаки и защиты
        private static void FullSqlInjectionDemo()
        {
            Console.WriteLine("\n1. Попытка входа с вредоносным вводом (имитация формы логина):");

            string[] maliciousPayloads = {
                "admin@example.com' --",
                "admin@example.com' OR '1'='1",
                "' OR ''='",
                "user1@test.com'; DROP TABLE Users; --",
                "admin@example.com' UNION SELECT name, type, id FROM sys.tables; --"
            };

            foreach (var payload in maliciousPayloads)
            {
                Console.WriteLine($"\n   Тестируем payload: {payload}");

                // УЯЗВИМАЯ версия (конкатенация)
                TryVulnerableLogin(payload);

                // ЗАЩИЩЁННАЯ версия (параметры)
                TrySafeLogin(payload);
            }

            Console.WriteLine("\n" + "".PadRight(80, '═'));
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("ВЫВОДЫ И РИСКИ SQL-ИНЪЕКЦИИ:");
            Console.WriteLine(" • Несанкционированный доступ к данным (обход аутентификации)");
            Console.WriteLine(" • Раскрытие всех пользователей и их ролей");
            Console.WriteLine(" • Возможность выполнить DROP TABLE, DELETE, UPDATE");
            Console.WriteLine(" • В реальных системах — кража паролей, персональных данных");
            Console.WriteLine(" • Возможный RCE (удалённое выполнение кода) через xp_cmdshell");
            Console.WriteLine("\nЕДИНСТВЕННАЯ НАДЁЖНАЯ ЗАЩИТА:");
            Console.WriteLine("   → ПАРАМЕТРИЗОВАННЫЕ ЗАПРОСЫ (как в TrySafeLogin)");
            Console.WriteLine("   → Хранение хешей паролей (BCrypt, Argon2)");
            Console.WriteLine("   → Принцип наименьших привилегий для пользователя БД");
            Console.WriteLine("   → Валидация и белые списки на стороне приложения");
            Console.ResetColor();
        }

        private static void TryVulnerableLogin(string email)
        {
            try
            {
                using (var conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    string sql = $"SELECT COUNT(*) FROM {tableName} WHERE Email = '{email}' AND Role = 'Administrator'";
                    using (var cmd = new SqlCommand(sql, conn))
                    {
                        int count = (int)cmd.ExecuteScalar();
                        if (count > 0)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("      ВЗЛОМ УДАЛСЯ! (уязвимый код) — вход как администратор!");
                        }
                        else
                        {
                            Console.WriteLine("      Вход отклонён (уязвимый код)");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      Ошибка (возможно, DROP TABLE): {ex.Message}");
            }
        }

        private static void TrySafeLogin(string email)
        {
            using (var conn = new SqlConnection(connectionString))
            {
                conn.Open();
                string sql = $"SELECT COUNT(*) FROM {tableName} WHERE Email = @Email AND Role = 'Administrator'";
                using (var cmd = new SqlCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@Email", email);
                    int count = (int)cmd.ExecuteScalar();
                    if (count > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("      Вход разрешён (безопасный код) — настоящий админ");
                    }
                    else
                    {
                        Console.WriteLine("      Вход отклонён — инъекция НЕ сработала!");
                    }
                    Console.ResetColor();
                }
            }
        }
    }
}
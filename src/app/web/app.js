(function () {
  "use strict";

  var form = document.getElementById("login-form");
  var submit = document.getElementById("submit");
  var errorBox = document.getElementById("error");
  var username = document.getElementById("username");
  var password = document.getElementById("password");
  var pwToggle = document.getElementById("pw-toggle");

  username.addEventListener("keydown", function (event) {
    if (event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    password.focus();
  });

  pwToggle.addEventListener("click", function () {
    var show = password.type === "password";
    var start = null;
    var end = null;
    try {
      start = password.selectionStart;
      end = password.selectionEnd;
    } catch (e) {}

    password.type = show ? "text" : "password";
    pwToggle.classList.toggle("on", show);
    pwToggle.setAttribute("aria-pressed", show ? "true" : "false");
    pwToggle.setAttribute("aria-label", show ? "Скрыть пароль" : "Показать пароль");

    if (show && start !== null) {
      try {
        password.setSelectionRange(start, end);
      } catch (e) {}
    }
  });

  function showError(message) {
    errorBox.textContent = message || "Не удалось войти. Попробуйте ещё раз.";
    errorBox.style.display = "block";
  }

  function hideError() {
    errorBox.textContent = "";
    errorBox.style.display = "none";
  }

  function showDone() {
    hideError();
    var fields = document.querySelectorAll(
      "#login-form label, #login-form input, #login-form button, #login-form p.sub"
    );
    Array.prototype.forEach.call(fields, function (el) {
      el.style.display = "none";
    });
    document.getElementById("done").style.display = "block";
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    hideError();

    if (!username.value || !password.value) {
      showError("Введите логин и пароль");
      return;
    }

    submit.disabled = true;
    var params = new URLSearchParams();
    params.set("client_id", "school21");
    params.set("grant_type", "password");
    params.set("username", username.value);
    params.set("password", password.value);

    fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString()
    })
      .then(function (response) {
        return response.json().then(function (data) {
          return { ok: response.ok, status: response.status, data: data };
        });
      })
      .then(function (result) {
        if (result.ok && result.data && result.data.redirect) {
          window.location.replace(result.data.redirect);
          return;
        }
        if (result.ok && result.data && result.data.done) {
          showDone();
          return;
        }
        if (result.data && result.data.error_description) {
          showError(result.data.error_description);
        } else {
          showError();
        }
      })
      .catch(function () {
        showError("Сервис временно недоступен. Попробуйте позже.");
      })
      .finally(function () {
        submit.disabled = false;
      });
  });
})();
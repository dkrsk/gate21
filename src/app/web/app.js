(function () {
  "use strict";

  var form = document.getElementById("login-form");
  var submit = document.getElementById("submit");
  var errorBox = document.getElementById("error");

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

    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;
    if (!username || !password) {
      showError("Введите логин и пароль");
      return;
    }

    submit.disabled = true;
    var params = new URLSearchParams();
    params.set("client_id", "school21");
    params.set("grant_type", "password");
    params.set("username", username);
    params.set("password", password);

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
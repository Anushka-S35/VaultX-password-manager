document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("loginForm");

  form.addEventListener("submit", (e) => {
    e.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    let users = JSON.parse(localStorage.getItem("users")) || [];
    let found = users.find(user => user.email === email && user.password === password);

    if (found) {
      localStorage.setItem("currentUser", JSON.stringify(found)); // save logged-in user
      window.location.href = "home.html";
    } else {
      alert("Invalid email or password");
    }
  });
});

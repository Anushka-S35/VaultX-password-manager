document.addEventListener("DOMContentLoaded", () => {
  const user = JSON.parse(localStorage.getItem("currentUser"));
  const tableBody = document.getElementById("accountsTableBody");

  if (!user) {
    alert("Please login first!");
    window.location.href = "login.html";
    return;
  }

  if (user.websites && user.websites.length > 0) {
    user.websites.forEach((acc, index) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${index + 1}</td>
        <td>${acc.site}</td>
        <td>${acc.username}</td>
        <td>${acc.password}</td>
      `;
      tableBody.appendChild(row);
    });
  } else {
    tableBody.innerHTML = `<tr><td colspan="4">No accounts saved yet</td></tr>`;
  }
});


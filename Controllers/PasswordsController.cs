using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using PasswordWallet.Models;
using PasswordWallet;

namespace PasswordWallet.Controllers
{
    public class PasswordsController : Controller
    {
        public string connectionString;

        private readonly IConfiguration _configuration;

        public PasswordsController(IConfiguration configuration)
        {
            _configuration = configuration;

            connectionString = _configuration.GetSection("ConnectionStrings").GetSection("DefaultConnection").Value;
        }


        // GET: Passwords
        public ActionResult Index()
        {
            List<Passwords> passwords = new List<Passwords>();
            Users user = new Users();

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords").ToList();

            for (int i = passwords.Count() - 1; i >= 0; i--)
            {
                user = db.Query<Users>("Select * From Users WHERE Id =" + passwords[i].IdUser).SingleOrDefault();

                passwords[i].Password = EncriptionHelper.DecryptPasswordAES(passwords[i].Password,
                                                                             user.PasswordHash);
            }

            return View(passwords);
        }

        // GET: Passwords/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Customer/Create
        [HttpPost]
        public ActionResult Create(Passwords passwords)
        {
            try
            {
                int rowsAffected;
                string sqlQuery;
                Users user = new Users();
                IDbConnection db = new SqlConnection(connectionString);

                user = db.Query<Users>("select * from Users where Id =" + passwords.IdUser).SingleOrDefault();

                passwords.Password = EncriptionHelper.EncryptPasswordAES(passwords.Password, user.PasswordHash);

                sqlQuery = "Insert Into Passwords (IdUser, Login, Description, WebAddress, Password) Values(@IdUser, @Login, @Description, @WebAddress, @Password)";

                rowsAffected = db.Execute(sqlQuery, passwords);

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }

        // GET: Passwords/Edit/5
        public ActionResult Edit(int idUser)
        {
            Passwords passwords = new Passwords();

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords WHERE idUser =" + idUser, new { idUser }).SingleOrDefault();

            return View(passwords);
        }

        // POST: Passwords/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int idUser, Passwords passwords)
        {
            try
            {
                IDbConnection db = new SqlConnection(connectionString);

                string sqlQuery = "UPDATE Passwords set " +
                        "Login='" + passwords.Login +
                        "',Password='" + passwords.Password +
                        "',WebAddress='" + passwords.WebAddress +
                        "',Description='" + passwords.Description +
                        "' WHERE idUser=" + passwords.IdUser;

                int rowsAffected = db.Execute(sqlQuery);

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }


        // GET: Passwords/Details/5
        public ActionResult Details(string password)
        {
            Passwords passwords = new Passwords();

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords WHERE Password = '" + password + "'").SingleOrDefault();
           // passwords.Password = EncriptionHelper.DecryptPasswordAES();

            return View(passwords);
        }

        // GET: Passwords/Delete/5
        public ActionResult Delete(int idUser)
        {
            Passwords passwords = new Passwords();

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords WHERE idUser =" + idUser, new { idUser }).SingleOrDefault();

            return View(passwords);
        }

        // POST: Passwords/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int idUser, IFormCollection collection)
        {
            try
            {
                IDbConnection db = new SqlConnection(connectionString);

                string sqlQuery = "Delete From Passwords WHERE idUser = " + idUser;

                int rowsAffected = db.Execute(sqlQuery);

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

    }
}
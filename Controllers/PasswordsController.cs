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
using Newtonsoft.Json;

namespace PasswordWallet.Controllers
{
    public class PasswordsController : Controller
    {
        public string connectionString;
        protected UserInfo userInfo;

        private readonly IConfiguration _configuration;

        public PasswordsController(IConfiguration configuration)
        {
            _configuration = configuration;

            connectionString = _configuration.GetSection("ConnectionStrings").GetSection("DefaultConnection").Value;
        }


        // GET: Passwords
        public ActionResult Index()
        {
            userInfo = JsonConvert.DeserializeObject<UserInfo>(HttpContext.Session.GetString("UserInfo"));

            List<Passwords> passwords;

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords where IdUser = " + userInfo.Id).ToList();

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
                userInfo = JsonConvert.DeserializeObject<UserInfo>(HttpContext.Session.GetString("UserInfo"));

                int rowsAffected;
                string sqlQuery;
                Users user;
                IDbConnection db = new SqlConnection(connectionString);

                user = db.Query<Users>("select * from Users where Id =" + userInfo.Id).SingleOrDefault();

                passwords.IdUser = userInfo.Id;
                passwords.Password = EncryptionHelper.EncryptPasswordAES(passwords.Password, userInfo.LoggedUserPassword);

                sqlQuery = "Insert Into Passwords (IdUser, Login, Description, WebAddress, Password) Values(@IdUser, @Login, @Description, @WebAddress, @Password)";

                rowsAffected = db.Execute(sqlQuery, passwords);

                return RedirectToAction(nameof(Index), new { idUser = passwords.IdUser });
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
            Passwords passwords;

            userInfo = JsonConvert.DeserializeObject<UserInfo>(HttpContext.Session.GetString("UserInfo"));

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords WHERE Password = '" + password + "'").SingleOrDefault();
            
            passwords.Password = EncryptionHelper.DecryptPasswordAES(passwords.Password, userInfo.LoggedUserPassword);

            return View(passwords);
        }

        // GET: Passwords/Delete/5
        public ActionResult Delete(string password)
        {
            Passwords passwords;
            userInfo = JsonConvert.DeserializeObject<UserInfo>(HttpContext.Session.GetString("UserInfo"));

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords WHERE idUser = " + userInfo.Id + " AND " + " password = '" + password + "'").SingleOrDefault();

            return View(passwords);
        }

        // POST: Passwords/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(string id, IFormCollection collection)
        {
            try
            {
                string passwordHash = collection["PasswordHash"];
                IDbConnection db = new SqlConnection(connectionString);

                string sqlQuery = "Delete From Passwords WHERE password = '" + passwordHash + "'";
                //string sqlQuery = "Delete From Passwords WHERE idUser = " + passwords.IdUser + " AND " + " password = '" + password + "'";

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
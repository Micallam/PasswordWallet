using Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using PasswordWallet.Models;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PasswordWallet;

namespace PasswordWallet.Controllers
{
    public class UsersController : Controller
    {
        private static readonly Random random = new Random();
        private const string  pepper = "Pepper";
        public string connectionString;

        private readonly IConfiguration _configuration;

        public UsersController(IConfiguration configuration)
        {
            _configuration = configuration;

            connectionString = _configuration.GetSection("ConnectionStrings").GetSection("DefaultConnection").Value;
        }

        // GET: Users
        public ActionResult Index()
        {
            List<Users> users;

            IDbConnection db = new SqlConnection(connectionString);

            users = db.Query<Users>("Select * From Users").ToList();

            return View(users);
        }

        // GET: Users/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Users/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(Users users)
        {
            try
            {
                IDbConnection db = new SqlConnection(connectionString);

                users.Salt          = getSalt();

                users.PasswordHash = users.IsPasswordKeptAsHash ?
                    GetPasswordHashSHA512(users.PasswordHash, users.Salt, pepper) :
                    GetPasswordHMAC(users.PasswordHash, users.Salt, pepper);

                string sqlQuery = "Insert Into Users (Salt, PasswordHash, Login, IsPasswordKeptAsHash) Values(@Salt, @PasswordHash, @Login, @IsPasswordKeptAsHash)";

                int rowsAffected = db.Execute(sqlQuery, users);

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: Users/Edit/5
        public ActionResult Edit(int id)
        {
            IDbConnection db = new SqlConnection(connectionString);

            Users users = db.Query<Users>("select * from Users where Id =" + id, new { id }).SingleOrDefault();
            UserPasswords userPasswords = new UserPasswords
            {
                Id = users.Id,
                PasswordHash = users.PasswordHash,
                IsPasswordKeptAsHash = users.IsPasswordKeptAsHash
            };

            return View(userPasswords);
        }

        // POST: Users/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, UserPasswords userPasswords)
        {
            try
            {
                Users users = new Users
                {
                    Salt = getSalt(),
                    Id = userPasswords.Id,
                    IsPasswordKeptAsHash = userPasswords.IsPasswordKeptAsHash
                };
                
                users.PasswordHash = userPasswords.IsPasswordKeptAsHash ?
                    GetPasswordHashSHA512(userPasswords.NewPassword, users.Salt, pepper) :
                    GetPasswordHMAC(userPasswords.NewPassword, users.Salt, pepper);

                this.UpdateUserPasswords(users, userPasswords.PasswordHash);

                IDbConnection db = new SqlConnection(connectionString);

                string sqlQuery = "UPDATE Users set " +
                        "Salt='" + users.Salt +
                        "',PasswordHash='" + users.PasswordHash +
                        "',IsPasswordKeptAsHash='" + users.IsPasswordKeptAsHash +
                        "' WHERE Id=" + users.Id;

                int rowsAffected = db.Execute(sqlQuery);

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        public int UpdateUserPasswords(Users _user, string _oldPasswordHash)
        {
            List<Passwords> passwords = new List<Passwords>();
            int affectedRows = 0;

            IDbConnection db = new SqlConnection(connectionString);

            passwords = db.Query<Passwords>("Select * From Passwords where IdUser = " + _user.Id).ToList();

            for (int i = passwords.Count() - 1; i >= 0; i--)
            {
                String encryptedPassword = passwords[i].Password;
                String decryptedPassword = EncriptionHelper.DecryptPasswordAES(encryptedPassword, _oldPasswordHash);

                affectedRows += db.Execute(
                    "update Passwords " +
                    "set Password = '" + EncriptionHelper.EncryptPasswordAES(decryptedPassword, _user.PasswordHash)
                    + "' where IdUser = " + _user.Id
                    + " and Password = '" + encryptedPassword + "'");
            }

            return affectedRows;
        }

        // GET: Users/Delete/5
        public ActionResult Delete(int id)
        {
            IDbConnection db = new SqlConnection(connectionString);

            Users users = db.Query<Users>("select * from Users where Id =" + id, new { id }).SingleOrDefault();

            return View(users);
        }

        // POST: Users/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                IDbConnection db = new SqlConnection(connectionString);

                string sqlQuery = "delete from Users where Id = " + id;

                int rowsAffected = db.Execute(sqlQuery, id);

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        public string getSalt()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, 10)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public string GetPasswordHashSHA512(string _password, string _salt, string _pepper = pepper)
        {
            return CalculateSHA512(_password + _salt + _pepper);
        }

        public string CalculateSHA512(string _secretText)
        {
            string secretText = _secretText ?? "";
            var encoding = new ASCIIEncoding();

            byte[] secretTextBytes = encoding.GetBytes(secretText);

            using (var sha512 = SHA512.Create())
            {
                byte[] hashmessage = sha512.ComputeHash(secretTextBytes);

                return Convert.ToBase64String(hashmessage);
            }
        }
        
        public string GetPasswordHMAC(string _password, string _salt, string _pepper = pepper)
        {
            return CalculateHMAC(_password, _salt + _pepper);
        }

        public string CalculateHMAC(string _secretText, string _key)
        {
            string secretText = _secretText ?? "";
            var encoding = new ASCIIEncoding();

            byte[] secretTextBytes = encoding.GetBytes(secretText);
            byte[] keyBytes = encoding.GetBytes(_key);

            using (var hmac = new HMACSHA512(keyBytes))
            {
                byte[] hashmessage = hmac.ComputeHash(secretTextBytes);

                return Convert.ToBase64String(hashmessage);
            }
        }
    }
}
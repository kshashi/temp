using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Security.Principal;
using MetLife.Annuities.Services.Data;
using MetLife.Annuities.Services.Security;
using System.Security.Authentication;
using MetLife.Annuities.Services.Advisors;
using MetLife.Annuities.Web.ViewModels;
using MetLife.Annuities.Web.Extensions;
using MetLife.Annuities.Services.Email;
using MetLife.Annuities.Web.Models;
using MetLife.Annuities.Services.Diagnostics;

namespace MetLife.Annuities.Web.Controllers
{
    [HandleError]
    public class AccountController : Controller
    {
        private IDataService DataService = new SqlDataService();
        private IUserService UserService = new IBSEUserService();
        private IAdvisorService AdvisorService = new AdvisorService();
        private IEmailService EmailService = new EmailService();
        private IRolesService RoleService = new IBSERolesService();

        [HttpGet]
        public ActionResult Index(string ReturnUrl)
        {
            bool isFirstTimeLoggingIn = false;

            // grab the header to use for getting user information
            string userId = Request.Headers[SiteConfiguration.SiteminderHeaderKey];

            // use the header information to get the user's role
            var roles = System.Web.Security.Roles.GetRolesForUser(userId);

            // make sure the roles are valid
            if (roles == null || roles.Length == 0 || roles.Length > 1)
            {
                return Redirect("~/public/pages/unauthorized.html");
            }

            var currentRole = roles[0].ToLower();

            // look for the user in the DB based on the role
            AnnuitiesUser user = null;
            user = GetIBANNMETUser(currentRole, userId);

            string systemId = "";
            if (currentRole == "advisor")
            {
                var advisor = AdvisorService.GetAdvisor(userId);
                systemId = advisor.system_id;
                //Log an activity that the user accessed annuities one-on-one                
                this.DataService.LogAdvisorLogon(systemId, Request.Headers["SM_SERVERSESSIONID"]);
            }

            // if the user is not found, 
            // create the user and get the information
            if (user == null)
            {
                // create the user in IBANNMET based on role
                user = CreateIBANNMETUser(currentRole, userId, systemId);
                isFirstTimeLoggingIn = true;
            }

            if (user != null && currentRole == "advisor")
            {
                // make sure system id is registered
                var ad = DataService.GetAdvisor(userId);
                ad.SystemID = systemId;
                DataService.SaveAdvisor(ad);
            }
            FormsAuthentication.SetAuthCookie(user.ExternalUserID, false);

            // handle role specific activities 
            if (currentRole == "admin")
            {
                if (!string.IsNullOrEmpty(ReturnUrl))
                    return Redirect(ReturnUrl);
                else
                    return RedirectToAction("index", new { controller = "Doc", area = "admins" });
            }

            if (currentRole == "rvp")
            {
                if (!string.IsNullOrEmpty(ReturnUrl) && !isFirstTimeLoggingIn)
                    return Redirect(ReturnUrl);
                else
                    return RedirectToAction("index", new { controller = "dashboard", area = "rvps", first_login = isFirstTimeLoggingIn ? 1 : 0 });
            }

            if (currentRole == "advisor")
            {
                if (isFirstTimeLoggingIn)
                {
                    var advisor = AdvisorService.GetAdvisor(userId);
                    AdvisorService.UpdateAdvisorStatus(advisor.universal_id, advisor.system_id, AdvisorStatus.AccountActivated);
                    return RedirectToAction("index", "dashboard", new { area = "advisors", first_login = isFirstTimeLoggingIn ? 1 : 0 });
                }
                else if (!string.IsNullOrEmpty(ReturnUrl))
                    return Redirect(ReturnUrl);
                else
                    return RedirectToAction("index", "dashboard", new { area = "advisors", first_login = isFirstTimeLoggingIn ? 1 : 0 });
            }

            if (currentRole == "client")
            {
                var client = DataService.GetClient(userId);
                bool hasSetupQuestions = client.SecurityQuestionsSet;
                if (isFirstTimeLoggingIn || hasSetupQuestions == false)
                    return Redirect("/account/questions");
                else if (!string.IsNullOrEmpty(ReturnUrl))
                    return Redirect(ReturnUrl);
                else
                    return Redirect("/clients/testimonials");
            }

            throw new ApplicationException("something went wrong...");
        }

        [HttpGet]
        public ActionResult LoginTest()
        {
            return View();
        }

        [HttpPost]
        public ActionResult LoginTest(string SM_UNIVERSALID)
        {
            FormsAuthentication.SignOut();

            // set the HTTP header
            Request.Headers.Add(SiteConfiguration.SiteminderHeaderKey, SM_UNIVERSALID);

            // redirect to the regular login 
            return Index("");
        }

        [HttpGet]
        public ActionResult Logoff()
        {
            
            FormsAuthentication.SignOut();
            if (Request.Cookies[Messages.DOCCODE] != null)
                Request.Cookies[Messages.DOCCODE].Expires = DateTime.Now.AddDays(-1);

            HttpCookie docCookie = new HttpCookie(Messages.DOCCODE);
            docCookie.Value = string.Empty;
            Response.Cookies.Add(docCookie);

            if (Request.Cookies[Messages.DOCCOMBINED] != null)
                Request.Cookies[Messages.DOCCOMBINED].Expires = DateTime.Now.AddDays(-1);

            HttpCookie stateDocCookie = new HttpCookie(Messages.DOCCOMBINED);
            stateDocCookie.Value = string.Empty;
            Response.Cookies.Add(stateDocCookie);

            var url = SiteConfiguration.SiteminderLogoutUrl;

            return Redirect(url);
        }

        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }

        public ActionResult Verify()
        {
            return View();
        }

        public ActionResult ChangePassword()
        {
            var model = new ForgotPasswordViewModel
            {
                Questions = new List<SecurityQuestion>() { new SecurityQuestion { } },
                Username = "testusername@aol.com"
            };
            //var username = TempData["username"].ToString();
            //var questions = UserService.GetUserSecurityQuestions(username, "");
            //if (questions.Count() == 0)
            //{
            //    TempData["error-msg"] = "Sorry, you did not set up account questions.";
            //}
            return View(model);
        }

        [HttpPost]
        public ActionResult ChangePassword(ForgotPasswordViewModel model)
        {

            if (string.IsNullOrEmpty(model.Password))
            {
                // coming in from the questions page
                int attempts = 0;
                foreach (var item in model.Questions)
                {
                    var correct = UserService.CheckSecurityQuestionAnswer(model.Username, "", item.QuestionNumber,
                        item.QuestionAnswer, out attempts);
                    if (!correct)
                    {
                        // return immediately
                        TempData["error-msg"] = "Incorrect security question answer(s)";
                        return RedirectToAction("forgotpassword", new { username = model.Username });
                    }

                }
                return View(model);
            }
            else
            {
                // posting back with new password
                if (model.Password != model.PasswordConfirm)
                {
                    TempData["error-msg"] = "Passwords do not match";
                    return View(model);
                }
                string status = string.Empty;
                var ques = new Dictionary<string, string>();
                foreach (var item in model.Questions)
                {
                    ques.Add(item.QuestionNumber, item.QuestionAnswer);

                }
                var success = UserService.ResetPassword(model.Username, ques, model.PasswordConfirm, out status);
                if (success == true)
                {
                    var client = DataService.GetClient(model.Username);
                    try
                    {
                        EmailService.SendPasswordResetEmail(client);
                    }
                    catch (MetLife.Annuities.Services.Email.DNSSException)
                    {
                        return Redirect("~/public/pages/dnss.html");
                    }

                    return RedirectToRoute(new { controller = "testimonials", action = "index", area = "clients" });
                }
                TempData["error-msg"] = status;
                return View(model);
            }


        }

        [HttpGet]
        public ActionResult CreatePassword(int id, Guid g)
        {
            if (Request.IsAuthenticated)
                FormsAuthentication.SignOut();
            var client = DataService.GetClient(id);
            if (client.UniqueId != g)
                throw new AuthenticationException();

            if (client != null && !string.IsNullOrWhiteSpace(client.UniversalID))
            {
                try
                {
                    var roles = RoleService.GetRolesForUser(client.UniversalID);
                    if (roles.Contains("Client"))
                        return RedirectToAction("testimonials", "clients");
                }
                catch
                {
                    //eating the Use does not exist exception
                }

            }


            return View(client);
        }

        [HttpPost]
        public ActionResult CreatePassword(int id, Guid g, string password, string confirm)
        {
            var client = DataService.GetClient(id);
            var adv = DataService.GetAdvisor(client.AdvisorID);
            var advisor = AdvisorService.GetAdvisor(adv.UniversalID);
            var existingUser = DataService.GetUserProfile(client.UserId);

            if (client.UniqueId != g)
                throw new AuthenticationException();
            if (password != confirm)
                return View(client);
            if (!string.IsNullOrEmpty(existingUser.ExternalID))
            {
                TempData["error-msg"] = "A user already exists with this login";
                return View(client);
            }

            CreateUserStatusDetails statusDetails;
            var user = UserService.CreateUser(client.EmailAddress, password, client.FirstName, client.LastName, out statusDetails);
            if (statusDetails.Status == CreateUserStatus.Success)
            {
                var profile = DataService.GetUserProfile(client.UserId);
                profile.ExternalID = user.UserName;
                DataService.SaveUserProfile(profile);
                DataService.UpdateClientProgress(client.ClientID, Services.ClientProgressType.PasswordSetup, advisor);

                var advisorStatus = (AdvisorStatus)advisor.current_status_id;
                if (advisorStatus != AdvisorStatus.ActiveClients)
                    AdvisorService.UpdateAdvisorStatus(advisor.universal_id, advisor.system_id, AdvisorStatus.ClientSetup);

                //return RedirectToAction("questions", "account");
                FormsAuthentication.SetAuthCookie(profile.ExternalID, false);
                return Redirect("/public/account/questions");
            }
            else
            {
                TempData["error-msg"] = statusDetails.StatusDesc;
                return View(client);
            }
        }

        [Authorize]
        public ActionResult Questions()
        {
            var questions = UserService.GetSecurityQuestions();
            return View(questions);
        }

        [Authorize(Roles = "Client")]
        [HttpPost]
        public ActionResult Questions(AccountQuestionsViewModel model)
        {

            var questions = from t in model.SecurityQuestion
                            select new SecurityQuestion
                            {
                                QuestionNumber = t.QuestionNumber,
                                QuestionAnswer = t.Answer,
                                QuestionAnswerConfirm = t.Confirm
                            };

            List<SecurityQuestion> state = new List<SecurityQuestion>();

            foreach (var question in questions)
            {
                if (question.QuestionAnswer != question.QuestionAnswerConfirm)
                {
                    TempData["error-msg"] = "All answers must be unique.";
                    state = UserService.GetSecurityQuestions();
                    return View(state);
                }
            }

            var response = UserService.SetSecurityQuestions(User.Identity.Name, "", questions.ToList(), false);
            if (response.Value == "OK")
            {
                var client = DataService.GetClient(User.Identity.Name);
                client.SecurityQuestionsSet = true;
                DataService.SaveClient(client, client.AdvisorID);

                return RedirectToAction("index", "testimonials", new { area = "clients" });
            }

            TempData["error-msg"] = response.Value;
            state = UserService.GetSecurityQuestions();
            return View(state);

        }


        //[HttpGet]
        //public ActionResult ForgotPassword()
        //{
        //    var model = new ForgotPasswordViewModel();
        //    return View(model);
        //}

        //[HttpPost]
        public ActionResult ForgotPassword(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                var model = new ForgotPasswordViewModel();
                return View(model);
            }
            string[] roles = null;

            try
            {
                roles = Roles.GetRolesForUser(username);

            }
            catch (Exception ex)
            {
                TempData["error-msg"] = "Sorry, we could not find this username";
                return View(new ForgotPasswordViewModel
                {
                    Questions = null,
                    Username = ""
                });
            }

            if (roles.Length == 0)
            {
                TempData["error-msg"] = "Sorry, no roles associated with this username";
                return View();
            }
            if (roles.First().ToLower() == "client")
            {
                try
                {
                    var questions = UserService.GetUserSecurityQuestions(username, "");
                    if (questions.Count() == 0)
                    {
                        TempData["error-msg"] = "Sorry, you didn't setup challenge questions";
                        return View();
                    }

                    questions.Shuffle();
                    questions = questions.Take(2).ToList();
                    var model = new ForgotPasswordViewModel
                    {
                        Questions = questions,
                        Username = username
                    };
                    return View(model);

                }
                catch (Exception ex)
                {
                    TempData["error-msg"] = "Error Occurred";
                    return View(new ForgotPasswordViewModel
                    {
                        Questions = null,
                        Username = ""
                    });
                }
            }
            else if (roles.First().ToLower() == "advisor")
            {
                var adv = this.AdvisorService.GetAdvisor(username);
                switch (adv.firm.firm_code.ToLower())
                {
                    case "mlf":
                        return Redirect(SiteConfiguration.MLFPortal);
                    case "nef":
                        return Redirect(SiteConfiguration.NEFPortal);
                    default:
                        return Redirect(SiteConfiguration.MLIPortal);
                }
            }
            else
            {
                return Redirect(SiteConfiguration.ForgotPasswordLink);
            }


        }
        public ActionResult Diagnostics()
        {

            var sql = new SqlServerDiagnostics();
            DiagnosticsIndexViewModel model = new DiagnosticsIndexViewModel
            {
                RequestHeaders = Request.Headers,
                ResponseHeaders = Response.Headers,
                Server = Server,
                SqlInfo = sql.TestConnection()
            };
            if (!SiteConfiguration.DisplayDiagnostics)
            {
                model = new DiagnosticsIndexViewModel
                {
                    RequestHeaders = new System.Collections.Specialized.NameValueCollection(),
                    ResponseHeaders = new System.Collections.Specialized.NameValueCollection(),
                    Server = null,
                    SqlInfo = string.Empty
                };
            }

            return View(model);
        }

        #region "Helper Methods"
        private void SyncAdvisorsForRvp(string userId)
        {
            throw new NotImplementedException();
        }

        private AnnuitiesUser GetIBANNMETUser(string currentRole, string userId)
        {

            var profile = DataService.GetUserProfileByExternalId(userId);
            if (profile == null)
                return null;

            return new AnnuitiesUser
            {
                UserID = profile.UserProfileID,
                ExternalUserID = userId
            };
        }

        private AnnuitiesUser CreateIBANNMETUser(string currentRole, string userId, string systemId)
        {
            var profile = DataService.CreateIBANNMETUser(currentRole, userId, systemId);
            return new AnnuitiesUser
            {
                UserID = profile.UserProfileID,
                ExternalUserID = userId
            };
        }

        #endregion
    }
}

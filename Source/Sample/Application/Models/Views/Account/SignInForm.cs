using System.ComponentModel.DataAnnotations;

namespace Application.Models.Views.Account
{
	public class SignInForm
	{
		#region Properties

		public virtual bool Cancel { get; set; }
		public virtual string ReturnUrl { get; set; }

		[Display(Name = "User-name")]
		[Required]
		public virtual string UserName { get; set; }

		#endregion
	}
}
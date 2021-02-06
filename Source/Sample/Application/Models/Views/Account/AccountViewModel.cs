using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Application.Models.Views.Account
{
	public class AccountViewModel
	{
		#region Properties

		public virtual IDictionary<string, string> AuthenticationProperties { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		public virtual IList<Claim> Claims { get; } = new List<Claim>();
		public virtual IList<string> Permissions { get; } = new List<string>();
		public virtual IList<string> Roles { get; } = new List<string>();
		public virtual string UserName { get; set; }

		#endregion
	}
}
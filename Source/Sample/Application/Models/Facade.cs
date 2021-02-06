using System;
using HansKindberg.Web.Authorization;
using Microsoft.Extensions.Logging;

namespace Application.Models
{
	public class Facade : IFacade
	{
		#region Constructors

		public Facade(IAuthorizationResolver authorizationResolver, ILoggerFactory loggerFactory)
		{
			this.AuthorizationResolver = authorizationResolver ?? throw new ArgumentNullException(nameof(authorizationResolver));
			this.LoggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
		}

		#endregion

		#region Properties

		public virtual IAuthorizationResolver AuthorizationResolver { get; }
		public virtual ILoggerFactory LoggerFactory { get; }

		#endregion
	}
}
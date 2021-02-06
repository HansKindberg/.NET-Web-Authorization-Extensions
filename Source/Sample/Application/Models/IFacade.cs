using HansKindberg.Web.Authorization;
using Microsoft.Extensions.Logging;

namespace Application.Models
{
	public interface IFacade
	{
		#region Properties

		IAuthorizationResolver AuthorizationResolver { get; }
		ILoggerFactory LoggerFactory { get; }

		#endregion
	}
}
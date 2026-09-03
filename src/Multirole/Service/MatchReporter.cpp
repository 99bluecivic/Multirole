#include "MatchReporter.hpp"

#include <memory>
#include <stdexcept>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/json.hpp>
#include <fmt/format.h>
#include <openssl/ssl.h>

#include "../I18N.hpp"
#include "LogHandler.hpp"

namespace Ignis::Multirole
{

namespace
{

constexpr auto HTTP_HEADER_FORMAT_STRING =
	"POST {:s} HTTP/1.1\r\n"
	"Host: {:s}\r\n"
	"User-Agent: DyXel-Multirole/1.0\r\n"
	"Content-Length: {:d}\r\n"
	"Content-Type: application/json\r\n\r\n";

} // namespace

class Service::MatchReporter::Connection final :
	public std::enable_shared_from_this<Service::MatchReporter::Connection>
{
public:
	using Endpoints = boost::asio::ip::tcp::resolver::results_type;

	Connection(boost::asio::io_context& ioCtx,
		std::shared_ptr<boost::asio::ssl::context> sslCtx,
		Endpoints endpoints, std::string payload, const std::string& host,
		const Service::MatchReporter& reporter)
		:
		sslCtx(std::move(sslCtx)),
		socket(ioCtx, *this->sslCtx),
		endpoints(std::move(endpoints)),
		payload(std::move(payload)),
		host(host),
		reporter(reporter)
	{
		using namespace boost::asio::ssl;
		if(SSL_set_tlsext_host_name(socket.native_handle(), host.c_str()) != 1)
			throw std::runtime_error("Unable to set TLS server name.");
		socket.set_verify_mode(verify_peer);
		socket.set_verify_callback(host_name_verification(host));
	}

	void DoConnect() noexcept
	{
		auto self(shared_from_this());
		boost::asio::async_connect(socket.lowest_layer(), endpoints,
		[this, self](boost::system::error_code ec, const auto&)
		{
			if(ec)
			{
				reporter.LogError(I18N::MATCH_REPORTER_CONNECT_ERROR, ec.message());
				return;
			}
			DoHandshake();
		});
	}

private:
	const std::shared_ptr<boost::asio::ssl::context> sslCtx;
	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket;
	const Endpoints endpoints;
	const std::string payload;
	const std::string host;
	const Service::MatchReporter& reporter;
	std::string readBuffer;

	void DoHandshake() noexcept
	{
		auto self(shared_from_this());
		socket.async_handshake(decltype(socket)::client,
		[this, self](boost::system::error_code ec)
		{
			if(ec)
			{
				reporter.LogError(I18N::MATCH_REPORTER_HANDSHAKE_ERROR, ec.message());
				return;
			}
			DoWrite();
		});
	}

	void DoWrite() noexcept
	{
		auto self(shared_from_this());
		boost::asio::async_write(socket, boost::asio::buffer(payload),
		[this, self](boost::system::error_code ec, std::size_t)
		{
			if(ec)
			{
				reporter.LogError(I18N::MATCH_REPORTER_WRITE_ERROR, ec.message());
				return;
			}
			DoRead();
		});
	}

	void DoRead() noexcept
	{
		auto self(shared_from_this());
		boost::asio::async_read_until(socket, boost::asio::dynamic_buffer(readBuffer),
			"\r\n\r\n",
		[this, self](boost::system::error_code ec, std::size_t)
		{
			if(ec)
			{
				reporter.LogError(I18N::MATCH_REPORTER_READ_ERROR, ec.message());
				return;
			}
			const auto lineEnd = readBuffer.find("\r\n");
			const auto statusLine = readBuffer.substr(0U, lineEnd);
			if(statusLine.find(" 2") == std::string::npos)
				reporter.LogError(I18N::MATCH_REPORTER_HTTP_ERROR, statusLine);
			DoShutdown();
		});
	}

	void DoShutdown() noexcept
	{
		auto self(shared_from_this());
		socket.async_shutdown([this, self](boost::system::error_code ec)
		{
			if(ec && ec != boost::asio::error::eof)
				reporter.LogError(I18N::MATCH_REPORTER_SHUTDOWN_ERROR, ec.message());
			boost::system::error_code ignored;
			socket.lowest_layer().shutdown(
				boost::asio::ip::tcp::socket::shutdown_both, ignored);
		});
	}
};

Service::MatchReporter::MatchReporter(boost::asio::io_context& ioCtx, Service::LogHandler& logHandler,
	const boost::json::object& cfg)
	:
	ioCtx(ioCtx),
	logHandler(logHandler),
	sslCtx(),
	scheme(),
	host(),
	path(),
	endpoints()
{
	const auto enabled = cfg.find("enabled");
	if(enabled == cfg.cend() || !enabled->value().as_bool())
		return;

	const auto& jsonUri = cfg.at("uri").as_string();
	const std::string_view uri(jsonUri.data(), jsonUri.size());
	const auto schemeColon = uri.find(':');
	if(schemeColon == std::string_view::npos)
		throw std::invalid_argument(I18N::MATCH_REPORTER_URI_INVALID);
	if(uri.substr(0U, schemeColon) != "https")
		throw std::invalid_argument(I18N::MATCH_REPORTER_HTTPS_REQUIRED);
	const auto authorityStart = schemeColon + 3U;
	if(authorityStart > uri.size())
		throw std::invalid_argument(I18N::MATCH_REPORTER_URI_INVALID);
	const auto pathStart = uri.find('/', authorityStart);
	scheme = "https";
	if(pathStart == std::string_view::npos)
	{
		host = std::string(uri.substr(authorityStart));
		path = "/";
	}
	else
	{
		host = std::string(uri.substr(authorityStart, pathStart - authorityStart));
		path = std::string(uri.substr(pathStart));
	}
	if(host.empty())
		throw std::invalid_argument(I18N::MATCH_REPORTER_URI_INVALID);

	sslCtx = std::make_shared<boost::asio::ssl::context>(
		boost::asio::ssl::context::sslv23);
	sslCtx->set_default_verify_paths();
	try
	{
		endpoints = boost::asio::ip::tcp::resolver(ioCtx).resolve(host, scheme);
		if(endpoints.empty())
			throw std::runtime_error(I18N::MATCH_REPORTER_RESOLVE_ERROR);
	}
	catch(const std::exception& e)
	{
		LogError(I18N::MATCH_REPORTER_RESOLVE_ERROR, e.what());
		sslCtx.reset();
	}
}

Service::MatchReporter::~MatchReporter() noexcept = default;

void Service::MatchReporter::LogError(std::string_view message, std::string_view detail) const noexcept
{
	try
	{
		if(detail.empty())
			logHandler.Log(ServiceType::MULTIROLE, Level::ERROR, message);
		else
		{
			std::string text(message);
			text += ' ';
			text += detail;
			logHandler.Log(ServiceType::MULTIROLE, Level::ERROR, text);
		}
	}
	catch(const std::exception& e)
	{
		logHandler.Log(ServiceType::MULTIROLE, Level::ERROR, message, e.what());
	}
}

void Service::MatchReporter::Report(const MatchReport& report) const noexcept
{
	if(!sslCtx)
		return;
	try
	{
		boost::json::object json;
		boost::json::array teams;
		for(std::size_t team = 0U; team < report.score.size(); ++team)
		{
			boost::json::object teamEntry;
			teamEntry.emplace("id", static_cast<int>(team));
			teamEntry.emplace("score", report.score[team]);
			boost::json::array players;
			for(const auto& player : report.players)
			{
				if(player.team != team)
					continue;
				boost::json::object entry;
				entry.emplace("name", player.name);
				entry.emplace("position", player.position);
				boost::json::object deck;
				auto AddCards = [](boost::json::object& obj, const char* key,
					const std::vector<uint32_t>& cards)
				{
					boost::json::array values;
					for(const auto code : cards)
						values.emplace_back(code);
					obj.emplace(key, std::move(values));
				};
				AddCards(deck, "main", player.main);
				AddCards(deck, "extra", player.extra);
				AddCards(deck, "side", player.side);
				entry.emplace("deck", std::move(deck));
				players.emplace_back(std::move(entry));
			}
			teamEntry.emplace("players", std::move(players));
			teams.emplace_back(std::move(teamEntry));
		}
		json.emplace("teams", std::move(teams));
		boost::json::array duels;
		for(const auto winner : report.duelWinners)
			duels.emplace_back(winner);
		json.emplace("duels", std::move(duels));

		const auto body = boost::json::serialize(json);
		auto payload = fmt::format(HTTP_HEADER_FORMAT_STRING, path, host, body.size());
		payload += body;
		std::make_shared<Connection>(
			ioCtx, sslCtx, endpoints, std::move(payload), host, *this)->DoConnect();
	}
	catch(const std::exception& e)
	{
		LogError(I18N::MATCH_REPORTER_REQUEST_ERROR, e.what());
	}
}

} // namespace Ignis::Multirole

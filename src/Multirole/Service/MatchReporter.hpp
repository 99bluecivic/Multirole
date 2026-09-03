#ifndef MULTIROLE_SERVICE_MATCHREPORTER_HPP
#define MULTIROLE_SERVICE_MATCHREPORTER_HPP
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/json/object.hpp>

#include "../Service.hpp"

namespace Ignis::Multirole
{

struct MatchReportPlayer
{
	std::string name;
	uint8_t team;
	uint8_t position;
	std::vector<uint32_t> main;
	std::vector<uint32_t> extra;
	std::vector<uint32_t> side;
};

struct MatchReport
{
	std::vector<MatchReportPlayer> players;
	std::array<uint32_t, 2U> score;
	std::vector<uint8_t> duelWinners;
};

class Service::MatchReporter final
{
public:
	MatchReporter(boost::asio::io_context& ioCtx, Service::LogHandler& logHandler,
		const boost::json::object& cfg);
	~MatchReporter() noexcept;

	void Report(const MatchReport& report) const noexcept;
private:
	class Connection;

	boost::asio::io_context& ioCtx;
	Service::LogHandler& logHandler;
	std::shared_ptr<boost::asio::ssl::context> sslCtx;
	std::string scheme;
	std::string host;
	std::string path;
	boost::asio::ip::tcp::resolver::results_type endpoints;

	void LogError(std::string_view message, std::string_view detail = {}) const noexcept;
};

} // namespace Ignis::Multirole

#endif // MULTIROLE_SERVICE_MATCHREPORTER_HPP

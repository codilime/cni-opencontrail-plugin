#include <mesos/hook.hpp>
#include <mesos/mesos.hpp>
#include <mesos/module.hpp>

#include <mesos/module/hook.hpp>

#include <mesos/mesos.pb.h>

class OpenContrailHook : public mesos::Hook
{
public:
	OpenContrailHook(std::string ip, std::string port) :
		ip_(std::move(ip)),
		port_(std::move(port))
	{
	}

	virtual Result<mesos::Environment> slaveExecutorEnvironmentDecorator(
			const mesos::ExecutorInfo& executorInfo)
	{
		mesos::Environment env;
		env.add_variables();
		auto var = env.mutable_variables()->Add();
		var->set_name("MESOS_SLAVE_PID");
		var->set_value("slave(1)@" + ip_ + ":" + port_);
		return env;
	}

private:
	std::string ip_;
	std::string port_;

};

static mesos::Hook* createHook(const mesos::Parameters& parameters)
{
	int size = parameters.parameter_size();
	std::string ip, port;
	for (int i = 0; i < size; ++i) {
		auto param = parameters.parameter(i);
		if (!param.has_key() || !param.has_value()) {
			continue;
		}
		if (param.key() == "ip") {
			ip = param.value();
		} else if (param.key() == "port") {
			port = param.value();
		}
	}
	return new OpenContrailHook(ip, port);
}

mesos::modules::Module<mesos::Hook> OpenContrailHookModule(
    MESOS_MODULE_API_VERSION,
    MESOS_VERSION,
    "Adam Niezurawski",
    "adam.niezurawski@codilime.com",
    "Hook for OpenContrail networking.",
    nullptr,
    createHook);

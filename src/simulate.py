# 1. Imports
from crewai import Agent, Task, Crew, Process
from crewai_tools import BaseTool
import json
from langchain_google_genai import ChatGoogleGenerativeAI  # Example LLM


# ----------------------------------------------------------------------------
# 2. Model Context Protocol Implementation: The "Security Data API" Toolset
# ----------------------------------------------------------------------------
# This class acts as a structured gateway to all our JSON data sources.
# It simulates a set of well-defined API endpoints, fulfilling the "Model Context Protocol"
# by providing a consistent and predictable way for agents to query data.

class SecurityDataAPIs(BaseTool):
    name: str = "Security Data API Gateway"
    description: str = "A unified toolset for querying all internal enterprise security and IT data sources."

    def __init__(self):
        # Load all our knowledge bases into memory on initialization
        self.cmdb = self._load_json('cmdb.json')
        self.iam = self._load_json('iam_hr_database.json')
        self.vlan_docs = self._load_json('network_architecture_vlan_documentation.json')
        self.service_policy = self._load_json('approved_port_service_usage_policy.json')
        self.threat_intel = self._load_json('threat_intelligence.json')
        self.ueba_profiles = self._load_json('user_entity_behaviour_analytics.json')
        self.edr_logs = self._load_json('endpoint_security_logs.json')
        self.vuln_scans = self._load_json('vulnerability_scan_database.json')
        self.proxy_dns_logs = self._load_json('web_proxy_dns_logs.json')
        self.playbooks = self._load_json('incident_response_playbooks.json')

    def _load_json(self, filepath):
        with open(filepath, 'r') as f:
            return json.load(f)

    # Each method below is a "tool" the LLM can call. The docstring is critical
    # as it tells the LLM what the tool does and what inputs it needs.

    def _run(self, query: str, entity_type: str):
        """
        The main query router for the API Gateway. Use this to find information.
        Example: query="192.168.2.55", entity_type="cmdb"
        """
        if entity_type == "cmdb":
            # Search logic for CMDB by IP, hostname, etc.
            return [asset for asset in self.cmdb['cmdb_assets'] if
                    query in [asset.get('ip_address'), asset.get('hostname')]]
        elif entity_type == "iam":
            # Search logic for IAM by username
            return [user for user in self.iam['iam_users'] if query == user.get('username')]
        elif entity_type == "threat_intel":
            # Search logic for Threat Intel by IP, domain, hash
            return [ioc for ioc in self.threat_intel['threat_intelligence_indicators'] if
                    query == ioc.get('indicator_value')]
        # ... Add similar query logic for all other data sources ...
        else:
            return "Error: Unknown entity_type. Must be one of [cmdb, iam, threat_intel, ...]"


# ----------------------------------------------------------------------------
# 3. Agent Definitions
# ----------------------------------------------------------------------------
# Instantiate the single toolset that all agents will use.
security_api_tools = SecurityDataAPIs()

# Define the LLM to be used by all agents
llm = ChatGoogleGenerativeAI(model="gemini-pro", temperature=0.2)

# Control Tower Agent Definition
control_tower_agent = Agent(
    role="Control Tower Agent",
    goal="Efficiently triage, dispatch, and manage incoming security alerts for deep analysis by specialized agents.",
    backstory=(
        "You are the central orchestrator of a Multi-Agent System for Cyber Incident Investigations. "
        "Your function is to act as an intelligent router, receiving alerts, performing rapid initial triage, "
        "and spawning an Issue Analysis Agent to conduct the full investigation. You track all parallel investigations and "
        "synthesize the final results for the human SOC team."
    ),
    llm=llm,
    tools=[security_api_tools],  # Has access to CMDB for initial triage.
    verbose=True
)

# Issue Analysis Agent Definition
issue_analysis_agent = Agent(
    role="Issue Analysis Agent",
    goal="Conduct a deep, rapid, and context-aware investigation into a single security alert, producing a definitive, evidence-backed conclusion and an actionable response plan.",
    backstory=(
        "You are a specialized and autonomous investigator. Your purpose is to receive a single task from the "
        "Control Tower and use all available data sources to enrich the alert. You must connect disparate data points, "
        "determine the root cause, assess the impact, and formulate a clear verdict. Your reasoning must be transparent and your output must be a complete JSON report."
    ),
    llm=llm,
    tools=[security_api_tools],  # Has full access to all data sources.
    verbose=True
)

# Overall Analysis Agent Definition (Note: In a real system, this would run periodically or in a separate process)
overall_analysis_agent = Agent(
    role="Overall Analysis Agent",
    goal="Analyze aggregated incident data over time to identify strategic patterns, emerging trends, and systemic risks.",
    backstory=(
        "You are a strategic intelligence synthesizer. You do not investigate single incidents. Instead, you consume the results of all completed investigations to see the big picture. "
        "Your goal is to convert incident data into organization-level intelligence, providing risk forecasts and long-term security recommendations."
    ),
    llm=llm,
    tools=[security_api_tools],  # Access to CMDB/IAM to enrich trend data.
    verbose=True
)

# ----------------------------------------------------------------------------
# 4. Task Definitions
# ----------------------------------------------------------------------------

# This task simulates the Control Tower's initial triage and handoff.
control_tower_task = Task(
    description=(
        "You have received the following security alert: {alert_json}\n\n"
        "1. Perform an initial triage by querying the CMDB for the primary asset's business criticality.\n"
        "2. Based on the criticality, formulate a precise and detailed investigation plan for the Issue Analysis Agent.\n"
        "3. Your final output must be this investigation plan, which will be handed to the next agent."
    ),
    expected_output="A clear, step-by-step investigation plan for the Issue Analysis Agent.",
    agent=control_tower_agent
)

# This task is the core of the investigation, performed by the Issue Analysis Agent.
issue_analysis_task = Task(
    description=(
        "Using the investigation plan provided by the Control Tower, you must now conduct a full investigation of the alert.\n"
        "Follow the plan meticulously, using your available tools to query all relevant data sources.\n"
        "You MUST correlate information from CMDB, IAM, Threat Intel, EDR, Vulnerability Scans, and all other logs.\n"
        "Your final output MUST be a single, complete JSON object that strictly adheres to the 'Automated Analysis Report' schema. "
        "This includes the final verdict, calculated severity, an evidence locker, and a course of action with a recommended playbook."
    ),
    expected_output="The final, complete 'Automated Analysis Report' in JSON format.",
    agent=issue_analysis_agent,
    context=[control_tower_task]  # This task depends on the output of the control tower's task.
)


# ----------------------------------------------------------------------------
# 5. Crew Definition and Execution
# ----------------------------------------------------------------------------

def run_investigation_crew(alert_to_investigate):
    # For a single incident, we form a crew with the Control Tower and Issue Analysis agents.
    # The Overall Analysis agent would be part of a separate, long-running 'Strategic Crew'.
    incident_crew = Crew(
        agents=[control_tower_agent, issue_analysis_agent],
        tasks=[control_tower_task, issue_analysis_task],
        process=Process.sequential,  # The process is sequential: Triage -> Investigate
        verbose=2
    )

    # Kick off the investigation
    result = incident_crew.kickoff(inputs={'alert_json': json.dumps(alert_to_investigate)})
    return result


# --- Main Execution Block ---
if __name__ == "__main__":
    print("## Initializing Multi-Agent Cyber Investigation System ##")

    # Load a sample alert to investigate (e.g., the Unauthorized USB Device alert)
    sample_alert = {
        "alert_id": "21006",
        "description": "An unauthorized USB device was connected to a workstation in the Finance department.",
        "details": {
            "hostname": "Workstation-Finance03",
            "user": "p.davis",
            "device_name": "USBSTOR\\...\\RubberDucky",
            "vendor_id": "1dd7"
        }
    }

    # Run the crew to get the final analysis report
    final_report = run_investigation_crew(sample_alert)

    print("\n\n## Investigation Complete ##")
    print("## Final Automated Analysis Report: ##")
    print(final_report)
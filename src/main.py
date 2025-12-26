"""
Main application entry point
"""
import logging
import sys
import os
import time

# Add src to path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import click
from core.config.settings import settings

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
def cli():
    """Behavioral Anomaly Detection Agent CLI"""
    click.echo("🤖 Behavioral Anomaly Detection Agent")
    click.echo("=" * 40)


@cli.command()
def generate_data():
    """Generate fake user behavior data for testing"""
    try:
        from data.fake_data_generator import FakeDataGenerator

        click.echo("🔄 Generating fake user behavior data...")
        generator = FakeDataGenerator()
        generator.generate_dataset()
        click.echo("✅ Data generation completed!")

    except Exception as e:
        click.echo(f"❌ Error generating data: {e}")


@cli.command()
def train_models():
    """Train anomaly detection models"""
    try:
        from ml.simple_anomaly_detector import SimpleAnomalyDetector

        click.echo("🧠 Training anomaly detection model...")
        detector = SimpleAnomalyDetector()
        detector.train("data/user_behavior.csv")
        click.echo("✅ Model training completed!")

    except Exception as e:
        click.echo(f"❌ Error training model: {e}")


@cli.command()
def detect_anomalies():
    """Run anomaly detection on generated data"""
    try:
        from ml.simple_anomaly_detector import SimpleAnomalyDetector

        click.echo("🔍 Running anomaly detection...")
        detector = SimpleAnomalyDetector()
        detector.train("data/user_behavior.csv")
        results = detector.batch_analyze("data/user_behavior.csv")

        # Show summary
        suspicious = [r for r in results if r['is_suspicious']]
        click.echo(f"\n📊 DETECTION SUMMARY:")
        click.echo(f"   Total Events: {len(results)}")
        click.echo(f"   Suspicious Events: {len(suspicious)}")
        click.echo(f"   Detection Rate: {len(suspicious)/len(results)*100:.1f}%")

        # Show top suspicious events
        if suspicious:
            click.echo(f"\n🚨 TOP 3 MOST SUSPICIOUS EVENTS:")
            for i, result in enumerate(sorted(suspicious, key=lambda x: x['overall_risk_score'], reverse=True)[:3]):
                click.echo(f"\n{i+1}. {result['event'].get('user_name', 'Unknown User')}")
                click.echo(f"   📅 {result['event'].get('timestamp', 'Unknown time')}")
                click.echo(f"   🎯 Risk Score: {result['overall_risk_score']:.2f}/1.0")
                click.echo(f"   🚨 Alert Level: {result['alert_level']}")
                click.echo(f"   ⚠️  Issues: {', '.join(result['anomalies'][:2])}")

    except Exception as e:
        click.echo(f"❌ Error detecting anomalies: {e}")


@cli.command()
def demo():
    """Run complete demo: generate data, train model, detect anomalies"""
    click.echo("🚀 Running complete demo...")

    # Generate data
    click.echo("\n📊 Step 1: Generating fake data...")
    try:
        from data.fake_data_generator import FakeDataGenerator
        generator = FakeDataGenerator()
        generator.generate_dataset()
        click.echo("✅ Data generated successfully!")
    except Exception as e:
        click.echo(f"❌ Data generation failed: {e}")
        return

    # Train and detect
    click.echo("\n🧠 Step 2: Training model and detecting anomalies...")
    try:
        from ml.simple_anomaly_detector import SimpleAnomalyDetector
        detector = SimpleAnomalyDetector()
        detector.train("data/user_behavior.csv")
        results = detector.batch_analyze("data/user_behavior.csv")

        # Show results
        suspicious = [r for r in results if r['is_suspicious']]
        click.echo(f"\n🎉 DEMO COMPLETED SUCCESSFULLY!")
        click.echo(f"📊 Processed {len(results)} user behavior events")
        click.echo(f"🚨 Detected {len(suspicious)} suspicious activities")
        click.echo(f"🎯 Your AI agent is working! 🤖")

    except Exception as e:
        click.echo(f"❌ Demo failed: {e}")


@cli.command()
def start_api():
    """Start the API server"""
    click.echo(f"🚀 Starting {settings.APP_NAME} v{settings.VERSION}")
    click.echo(f"📡 API will run on {settings.API_HOST}:{settings.API_PORT}")
    click.echo("⚠️  TODO: Implement API startup")


@cli.command()
@click.option('--input-file', help='Path to data file')
def process_data(input_file):
    """Process behavioral data"""
    if input_file:
        click.echo(f"📊 Processing data from: {input_file}")
    else:
        click.echo("📈 Processing real-time data stream...")
    click.echo("⚠️  TODO: Implement data processing")


@cli.command()
def status():
    """Show system status"""
    click.echo("📋 System Status:")
    click.echo(f"   App: {settings.APP_NAME}")
    click.echo(f"   Version: {settings.VERSION}")
    click.echo(f"   Debug: {settings.DEBUG}")

    # Check if data exists
    if os.path.exists("data/user_behavior.csv"):
        click.echo("   Data: ✅ Training data available")
    else:
        click.echo("   Data: ❌ No training data (run 'generate-data' first)")

    click.echo("   Status: ✅ Ready for anomaly detection")


@cli.command()
def start_real_monitoring():
    """Start monitoring real data sources"""
    click.echo("🔌 Starting real-time data source monitoring...")

    try:
        from data.data_source_manager import create_data_manager

        # Create and start data manager
        manager = create_data_manager()
        manager.start_all_connectors()

        click.echo("📊 Monitoring started! Press Ctrl+C to stop...")

        try:
            # Keep monitoring until user stops
            while True:
                time.sleep(10)
                stats = manager.get_stats()
                click.echo(f"📈 Events: {stats['total_events']}, Active: {stats['active_connectors']}")

        except KeyboardInterrupt:
            click.echo("\n⏹️ Stopping monitoring...")
            manager.stop_all_connectors()

            # Export collected events
            manager.export_events("data/real_events.csv")
            click.echo("✅ Real data monitoring stopped and exported!")

    except Exception as e:
        click.echo(f"❌ Error in real monitoring: {e}")


@cli.command()
def test_real_data():
    """Test real data source connections"""
    click.echo("🔍 Testing real data source connections...")

    try:
        from data.data_source_manager import create_data_manager

        manager = create_data_manager()

        # Test each connector
        for name, connector in manager.connectors.items():
            click.echo(f"\n📡 Testing {name}...")

            if connector.connect():
                click.echo(f"✅ {name}: Connection successful")

                # Try to fetch a few events
                events = list(connector.fetch_events())
                if events:
                    click.echo(f"📊 {name}: Found {len(events)} recent events")
                    sample_event = connector.parse_event(events[0])
                    if sample_event:
                        click.echo(f"🔍 Sample event: {sample_event.get('event_type')} by {sample_event.get('user_name')}")
                else:
                    click.echo(f"📭 {name}: No recent events found")

            else:
                click.echo(f"❌ {name}: Connection failed")

    except Exception as e:
        click.echo(f"❌ Error testing real data: {e}")


@cli.command()
def analyze_real_data():
    """Analyze real data with anomaly detection"""
    click.echo("🔍 Analyzing real data for anomalies...")

    try:
        # Check if we have real data
        if not os.path.exists("data/real_events.csv"):
            click.echo("❌ No real data found. Run 'start-real-monitoring' first!")
            return

        from ml.simple_anomaly_detector import SimpleAnomalyDetector

        # Train detector on real data
        detector = SimpleAnomalyDetector()
        detector.train("data/real_events.csv")

        # Analyze real events
        results = detector.batch_analyze("data/real_events.csv")

        # Show results
        suspicious = [r for r in results if r['is_suspicious']]
        click.echo(f"\n📊 REAL DATA ANALYSIS RESULTS:")
        click.echo(f"   Total Events: {len(results)}")
        click.echo(f"   Suspicious Events: {len(suspicious)}")
        click.echo(f"   Detection Rate: {len(suspicious)/len(results)*100:.1f}%")

        if suspicious:
            click.echo(f"\n🚨 TOP 5 REAL THREATS DETECTED:")
            for i, result in enumerate(sorted(suspicious, key=lambda x: x['overall_risk_score'], reverse=True)[:5]):
                click.echo(f"\n{i+1}. {result['event'].get('user_name', 'Unknown User')}")
                click.echo(f"   📅 {result['event'].get('timestamp', 'Unknown time')}")
                click.echo(f"   🎯 Risk Score: {result['overall_risk_score']:.2f}/1.0")
                click.echo(f"   🚨 Alert Level: {result['alert_level']}")
                click.echo(f"   📡 Source: {result['event'].get('source_connector', 'Unknown')}")
                click.echo(f"   ⚠️  Issues: {', '.join(result['anomalies'][:2])}")

        click.echo(f"\n🎯 Your AI is now detecting REAL security threats! 🔥")

    except Exception as e:
        click.echo(f"❌ Error analyzing real data: {e}")


@cli.command()
def setup_real_data():
    """Setup real data source configuration"""
    click.echo("⚙️ Setting up real data source configuration...")

    import json

    config = {
        "linux_auth": {
            "enabled": True,
            "log_files": ["/var/log/auth.log", "/var/log/secure"],
            "poll_interval": 5,
            "description": "Monitor SSH logins, sudo commands, authentication events"
        },
        "web_logs": {
            "enabled": True,
            "log_files": [
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
                "/var/log/httpd/access_log"
            ],
            "poll_interval": 10,
            "description": "Monitor web application access and downloads"
        },
        "database": {
            "enabled": False,
            "db_type": "mysql",
            "log_files": ["/var/log/mysql/mysql.log"],
            "database": {
                "host": "localhost",
                "user": "monitor_user",
                "password": "CHANGE_THIS",
                "database": "mysql"
            },
            "poll_interval": 15,
            "description": "Monitor database queries and suspicious SQL"
        },
        "file_monitoring": {
            "enabled": False,
            "watch_directories": [
                "/home",
                "/var/www",
                "/opt"
            ],
            "file_extensions": [".txt", ".doc", ".pdf", ".xlsx", ".csv"],
            "description": "Monitor file access and modifications"
        }
    }

    # Save config
    os.makedirs("data", exist_ok=True)
    with open("data/real_data_config.json", "w") as f:
        json.dump(config, f, indent=2)

    click.echo("✅ Configuration saved to data/real_data_config.json")
    click.echo("\n📋 Available Data Sources:")

    for source, conf in config.items():
        status = "✅ ENABLED" if conf["enabled"] else "❌ DISABLED"
        click.echo(f"\n🔌 {source.upper()} {status}")
        click.echo(f"   📝 {conf['description']}")
        if conf.get("log_files"):
            click.echo(f"   📄 Files: {', '.join(conf['log_files'])}")

    click.echo(f"\n⚙️ To enable more sources, edit: data/real_data_config.json")
    click.echo(f"🚀 Then run: python main.py start-real-monitoring")


if __name__ == "__main__":
    cli()


import neo4j

from cartography.intel import create_indexes
from tests.integration import settings


def test_neo4j_connection():
    driver = neo4j.GraphDatabase.driver(settings.get("NEO4J_URL"))
    with driver.session() as session:
        session.run("CALL db.indexes();")


def test_create_indexes(neo4j_session):
    # ensure the idempotency of creating indexes
    create_indexes.run(neo4j_session, None)
    create_indexes.run(neo4j_session, None)

"""Agent endpoints — list and detail."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aktov_cloud.api.deps import get_current_org
from aktov_cloud.database import get_db
from aktov_cloud.models.agent import Agent
from aktov_cloud.models.organization import Organization

router = APIRouter(prefix="/v1/agents", tags=["agents"])


class AgentDetail(BaseModel):
    id: str
    org_id: str
    agent_id_external: str
    agent_type: str | None = None
    declared_intent: str | None = None
    framework: str | None = None
    first_seen: datetime
    last_seen: datetime | None = None

    @classmethod
    def from_model(cls, agent: Agent) -> AgentDetail:
        return cls(
            id=str(agent.id),
            org_id=str(agent.org_id),
            agent_id_external=agent.agent_id_external,
            agent_type=agent.agent_type,
            declared_intent=agent.declared_intent,
            framework=agent.framework,
            first_seen=agent.first_seen,
            last_seen=agent.last_seen,
        )


class AgentListResponse(BaseModel):
    agents: list[AgentDetail]


@router.get("", response_model=AgentListResponse)
async def list_agents(
    org: Organization = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> AgentListResponse:
    result = await db.execute(
        select(Agent)
        .where(Agent.org_id == org.id)
        .order_by(Agent.last_seen.desc().nullslast())
    )
    agents = result.scalars().all()
    return AgentListResponse(agents=[AgentDetail.from_model(a) for a in agents])


@router.get("/{agent_id}", response_model=AgentDetail)
async def get_agent(
    agent_id: uuid.UUID,
    org: Organization = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> AgentDetail:
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.org_id == org.id)
    )
    agent = result.scalar_one_or_none()

    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found.")

    return AgentDetail.from_model(agent)

# Python Substrate Interface Library
#
# Copyright 2018-2020 Stichting Polkascan (Polkascan Foundation).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from datetime import datetime, timedelta

from substrateinterface.plugins import Plugin


class SubstrateNodePlugin(Plugin):

    supported_filters = ('block_start', 'block_end', 'account_id', 'pallet_name', 'event_name')

    def __init__(self, max_block_range=100):
        self.max_block_range = max_block_range
        super().__init__()

    def filter_events(self, block_start: int = None, block_end: int = None, pallet_name: str = None,
                      event_name: str = None, account_id: str = None):

        if block_end is None:
            block_end = self.substrate.get_block_number(None)

        if block_start is None:
            block_start = block_end

        # Requirements check
        if block_end - block_start > self.max_block_range:
            raise ValueError(f"max_block_range ({self.max_block_range}) exceeded")

        result = []

        for block_number in range(block_start, block_end + 1):
            block_hash = self.substrate.get_block_hash(block_number)
            for event in self.substrate.get_events(block_hash=block_hash):
                if pallet_name is not None and pallet_name != event.event_module.name:
                    continue

                if event_name is not None and event_name != event.event.name:
                    continue

                if account_id is not None:
                    found = False
                    for param in event.params:
                        if param['type'] == 'AccountId' and param['value'] == account_id:
                            found = True
                            break
                    if not found:
                        continue

                result.append(event)

        return result

    def search_block_id(self, block_datetime: datetime, accuracy: timedelta):
        raise NotImplementedError()

